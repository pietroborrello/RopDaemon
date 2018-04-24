#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
import random
from struct import pack, unpack
from itertools import permutations, combinations, chain
from multiprocessing import Pool
from tqdm import *
from ropper import RopperService
from Gadget import Gadget, Operations, Types
from Gadget import *
import capstone
from capstone.x86 import *
from unicorn import *
from unicorn.x86_const import *
import Arch
import logging


# memory address where emulation starts
ADDRESS = 0x1000000
MAX_BYTES_PER_INSTR = 0xf
HOOK_ERR_VAL = 0x1
MAX_RETN = 0x10
unsafe_classes = [X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_INT]

FLAGS_MASK = 0xd5



def filter_unsafe(gadgets):
    safe_gadgets = []
    for g in gadgets:
        unsafe = False
        for i in Arch.md.disasm(g.hex, g.address):
            if any(x in i.groups for x in unsafe_classes):
                unsafe = True
        if not unsafe:
            safe_gadgets.append(g)
    return safe_gadgets

def checkLoadConstGadget(init_regs, init_stack, final_state, gadget):
    result = []
    for r in gadget.modified_regs:
        for off in [i for i, x in enumerate(
            init_stack) if x == final_state[r]]:
                #don't overlap with ret address: load register inside gadget stack occupation
                if off < gadget.stack_fix - (Arch.ARCH_BITS/8) and off > 0:
                    result.append(LoadConst_Gadget(r, off*(Arch.ARCH_BITS/8), gadget))
    return result


def checkCopyRegGadget(init_regs, init_stack, final_state, gadget):
    result = []
    for r in gadget.modified_regs:
        #inverse lookup by value
        for src in [key for key, value in init_regs.items()
                        if value == final_state[r]]:
            if final_state[src] == init_regs[src]:
                result.append(CopyReg_Gadget(r, src, gadget))
    return result

def compute_operation(a, op, b):
    if op == Operations.ADD:
        return (a + b) & Arch.MAX_INT
    elif op == Operations.SUB:
        return (a - b) & Arch.MAX_INT
    elif op == Operations.MUL:
        return (a * b) & Arch.MAX_INT
    elif op == Operations.DIV:
        return (a // b) & Arch.MAX_INT
    elif op == Operations.XOR:
        return (a ^ b) & Arch.MAX_INT
    elif op == Operations.OR:
        return (a | b) & Arch.MAX_INT
    elif op == Operations.AND:
        return (a & b) & Arch.MAX_INT


def is_commutative(op, ):
    if op == Operations.ADD:
        return True
    elif op == Operations.SUB:
        return False
    elif op == Operations.MUL:
        return True
    elif op == Operations.DIV:
        return False
    elif op == Operations.XOR:
        return True
    elif op == Operations.OR:
        return True
    elif op == Operations.AND:
        return True



def checkBinOpGadget(init_regs, init_stack, final_state, gadget):
    result = []
    #TODO: overapproximating trivial operations (src1 must be != src2, and div must not give 0)
    for op in Operations:
        if is_commutative(op):
            for src1, src2 in combinations(Arch.regs, 2):
                op_res = compute_operation(
                    init_regs[src1], op, init_regs[src2])
                for dest in [r for r in final_state if final_state[r] == op_res and r in gadget.modified_regs]:
                    result.append(BinOp_Gadget(dest, src1, op, src2, gadget))
        else:
            # if DIV, only valid EAX=EAX/src2, TODO: not op_res == 0 may miss some DIV gadgets
            if op == Operations.DIV:
                    for src2 in Arch.regs:
                        dest = Arch.Registers_a
                        src1 = Arch.Registers_a
                        # check real div of 64bits
                        div_op_res = ((init_regs[Arch.Registers_d] << Arch.ARCH_BITS) + init_regs[src1]) / init_regs[src2]
                        # check if result handled by hook_err
                        hook_op_res = ((HOOK_ERR_VAL << Arch.ARCH_BITS) + init_regs[src1]) / init_regs[src2]
                        # check if the gadget itself correctly zeroed EDX
                        op_res = compute_operation(init_regs[src1], op, init_regs[src2])
                        if final_state[dest] == div_op_res and src2 != Arch.Registers_a:
                            result.append(BinOp_Gadget(dest, src1, op, src2, gadget))
                        elif final_state[dest] == hook_op_res and src2 != Arch.Registers_a:
                            result.append(BinOp_Gadget(dest, src1, op, src2, gadget))
                        elif final_state[dest] == op_res and op_res != 0 and src2 != Arch.Registers_a:
                            result.append(BinOp_Gadget(dest, src1, op, src2, gadget))
            else:
                for src1, src2 in permutations(Arch.regs, 2):
                    op_res = compute_operation(
                        init_regs[src1], op, init_regs[src2])
                    for dest in [r for r in final_state if final_state[r] == op_res and r in gadget.modified_regs]:
                        result.append(BinOp_Gadget(dest, src1, op, src2, gadget))
                        
    return result

def hook_err(uc, int_num, user_data):
    #ip = uc.reg_read(Arch.IP_REG)
    #instr_bytes = str(uc.mem_read(ip, MAX_BYTES_PER_INSTR))
    #instr = Arch.md.disasm(instr_bytes, 0x0, count = 1).next()
    #print 'ERROR: interrupt %x, due to: %s %s' % (int_num, instr.mnemonic, instr.op_str)
    if int_num==0: #div by zero fault
        # probaly since EDX:EAX doesn't fit in 32 bits
        # if was real div_by_zero, after resume it will double fault, and re-handled as int 0x8
        # safely modify EDX, independently from init_value, that will be overwritten by div
        uc.reg_write(Arch.regs[Arch.Registers_d], HOOK_ERR_VAL)
        return True
    return False

# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    mapped_pages_ref = user_data
    mapped_pages = mapped_pages_ref[0]
    # limit number of possible mapped pages, due to REP MOVS
    if mapped_pages > 128:
        return False
    mapped_pages += 1
    mapped_pages_ref[0] = mapped_pages
    #memory access not necessarly aligned to page boundaries, so map two pages to be sure
    try:
        uc.mem_map((address // Arch.PAGE_SIZE) * Arch.PAGE_SIZE, 2 * Arch.PAGE_SIZE)
    except UcError as e:
        logging.warning('Invalid memory mapping for %x', ((address // Arch.PAGE_SIZE) * Arch.PAGE_SIZE))
    return True


#TODO: manage REP MOVS
# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    address_written = user_data[0]
    address_read = user_data[1]
    if access == UC_MEM_WRITE:
        #print("MEM WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        address_written[address] = value
    else:   # READ
        #value = unpack(Arch.PACK_VALUE, uc.mem_read(address, Arch.ARCH_BITS/8))[0]
        #check if previously written or stack
        if address not in address_written: #initialize if never written
            value = Arch.rand()
            try:
                uc.mem_write(address, pack(Arch.PACK_VALUE, value))
            except UcError as e:
                # probably due to REP MOVS
                return False
        else:
            #TODO: ignored real read size, only full registers
            value = unpack(Arch.PACK_VALUE, uc.mem_read(address, Arch.ARCH_BITS/8))[0]
        address_read[address] = value
        #print("MEM READ at 0x%x, data size = %u, value = 0x%x" % (address, size, value))


def checkReadMemGadget(
    rv_pairs1, final_values1, address_read1, rv_pairs2, final_values2, address_read2, gadget):
    result = []
    for dest in gadget.modified_regs:
        possible = set()
        for addr in [addr for addr in address_read1 if address_read1[addr] == final_values1[dest]]:
            for addr_reg in rv_pairs1:
                if addr_reg is not Arch.Registers_sp:
                    offset = (addr - rv_pairs1[addr_reg]) & Arch.MAX_INT
                    possible.add((dest, addr_reg, offset))
        for addr in [addr for addr in address_read2 if address_read2[addr] == final_values2[dest]]:
            for addr_reg in rv_pairs2:
                if addr_reg is not Arch.Registers_sp:
                    offset = (addr - rv_pairs2[addr_reg]) & Arch.MAX_INT
                    if (dest, addr_reg, offset) in possible:
                        result.append(ReadMem_Gadget(dest, addr_reg, offset, gadget))
    return result


def checkWriteMemGadget(
        rv_pairs1, address_written1, rv_pairs2, address_written2, gadget):
    result = []
    for src in Arch.regs_no_sp:
        possible = set()
        for addr in [addr for addr in address_written1 if address_written1[addr] == rv_pairs1[src]]:
            for addr_reg in rv_pairs1:
                if addr_reg is not Arch.Registers_sp:
                    offset = (addr - rv_pairs1[addr_reg]) & Arch.MAX_INT
                    possible.add((addr_reg, offset, src))
        for addr in [addr for addr in address_written2 if address_written2[addr] == rv_pairs2[src]]:
            for addr_reg in rv_pairs2:
                if addr_reg is not Arch.Registers_sp:
                    offset = (addr - rv_pairs2[addr_reg]) & Arch.MAX_INT
                    if (addr_reg, offset, src) in possible:
                        result.append(WriteMem_Gadget(addr_reg, offset, src, gadget))
    return result

# dest = [addr_reg + offset]
def checkReadMemOpGadget(
    rv_pairs1, final_values1, address_read1, rv_pairs2, final_values2, address_read2, gadget):
    result = []
    for dest in gadget.modified_regs:
        possible = set()
        for op in Operations:
            for addr in address_read1:
                if compute_operation(address_read1[addr], op, rv_pairs1[dest]) == final_values1[dest]:
                    # ignore bad div
                    if op == Operations.DIV and final_values1[dest] == 0:
                        continue
                    for addr_reg in rv_pairs1:
                        if addr_reg is not Arch.Registers_sp:
                            offset = (addr - rv_pairs1[addr_reg]) & Arch.MAX_INT
                            possible.add((dest, addr_reg, offset))
            for addr in address_read2:
                if compute_operation(address_read2[addr], op, rv_pairs2[dest]) == final_values2[dest]:
                    for addr_reg in rv_pairs2:
                        if addr_reg is not Arch.Registers_sp:
                            offset = (addr - rv_pairs2[addr_reg]) & Arch.MAX_INT
                            if (dest, addr_reg, offset) in possible:
                                result.append(ReadMemOp_Gadget(dest, op, addr_reg, offset, gadget))
    return result

# [addr_reg + offset] OP= src
def checkWriteMemOpGadget(
        rv_pairs1, address_read1, address_written1, rv_pairs2, address_read2, address_written2, gadget):
    result = []
    for src in Arch.regs_no_sp:
        possible = set()
        for op in Operations:
            for addr in address_written1:
                if addr in address_read1 and address_written1[addr] == compute_operation(address_read1[addr], op, rv_pairs1[src]):
                    # ignore bad div
                    if op == Operations.DIV and address_written1[addr] == 0:
                        continue
                    for addr_reg in rv_pairs1:
                        if addr_reg is not Arch.Registers_sp:
                            offset = (addr - rv_pairs1[addr_reg]) & Arch.MAX_INT
                            possible.add((addr_reg, offset, src))
            for addr in address_written2:
                if addr in address_read2 and address_written2[addr] == compute_operation(address_read2[addr], op, rv_pairs2[src]):
                    for addr_reg in rv_pairs2:
                        if addr_reg is not Arch.Registers_sp:
                            offset = (addr - rv_pairs2[addr_reg]) & Arch.MAX_INT
                            if (addr_reg, offset, src) in possible:
                                result.append(WriteMemOp_Gadget(addr_reg, offset, op, src, gadget))
    return result

#AH: = SF: ZF: xx: AF: xx: PF: 1: CF
# xx - unknown
# mask: 0xd5
# 2nd youngest bit of EFLAGS is set to 1 (reserved bit)
def checkLahfGadget(flags_init, final_flags, final_state, gadget):
    if flags_init == final_flags and Arch.Registers_a in gadget.modified_regs:
        ah = ((final_state[Arch.Registers_a] >> 8) & FLAGS_MASK) | 2
        if ah == (final_flags & FLAGS_MASK) | 2 :
            return [Lahf_Gadget(gadget)]
    return []


def checkOpEspGadget(init_regs1, final_state1, init_regs2, final_state2, gadget):
    # diff := stack_fix +/- register
    diff1 = final_state1[Arch.Registers_sp] - init_regs1[Arch.Registers_sp]
    diff2 = final_state2[Arch.Registers_sp] - init_regs2[Arch.Registers_sp]

    for r in Arch.regs_no_sp:
        stack_fix1 = compute_operation(diff1, Operations.SUB, init_regs1[r])
        stack_fix2 = compute_operation(diff2, Operations.SUB, init_regs2[r])
        if stack_fix1 == stack_fix2 and stack_fix1 + (Arch.ARCH_BITS / 8) > 0 and stack_fix1 + (Arch.ARCH_BITS / 8)< 0x1000:
            gadget.stack_fix = stack_fix1 + (Arch.ARCH_BITS / 8) + gadget.retn
            return [OpEsp_Gadget(r, Operations.ADD, gadget)]

    return []

def emulate(g): #gadget g
    try:
        mu = Uc(UC_ARCH_X86, Arch.UC_MODE)
        sp_init = ADDRESS + 0x112230
        rv_pairs = {}
        for r in Arch.regs_no_sp:
            rv_pairs[r] = Arch.rand()
        rv_pairs[Arch.Registers_sp] = sp_init
        rand_stack = []
        address_written = {}
        address_read = {}
        for i in range(8):
            value = Arch.rand()
            rand_stack.append(value)
            address_written[sp_init + (Arch.ARCH_BITS/8)*i] = value
        flags_init = Arch.rand() & FLAGS_MASK

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, g.hex)
        # initialize stack
        mu.reg_write(Arch.regs[Arch.Registers_sp], sp_init)
        #init registers with random values
        for r in Arch.regs_no_sp:
            mu.reg_write(Arch.regs[r], rv_pairs[r])
            #print r, hex(rv_pairs[r])
        mu.reg_write(Arch.FLAGS_REG, flags_init)
        #write stack
        for i in range(len(rand_stack)):
            mu.mem_write(mu.reg_read(Arch.regs[Arch.Registers_sp]) +
                            (Arch.ARCH_BITS / 8) * i, pack(Arch.PACK_VALUE, rand_stack[i]))
            #print hex(rand_stack[i])

        # intercept invalid memory events
        mapped_pages = 0
        mapped_pages_ref = [mapped_pages]
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, user_data=mapped_pages_ref)
        #intercept CPU errors (probably due to div)
        mu.hook_add(UC_HOOK_INTR, hook_err)
        # tracing all memory READ & WRITE access
        user_data = (address_written, address_read)
        mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ,
                    hook_mem_access, user_data=user_data)
        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + (g.address_end - g.address), timeout=2*UC_SECOND_SCALE)

        final_values = {}
        for r in Arch.regs:
            final_values[r] = mu.reg_read(Arch.regs[r])
        final_flags = mu.reg_read(Arch.FLAGS_REG)
        Uc.release_handle(mu)
        return (rv_pairs, final_values, rand_stack, sp_init, address_written, address_read, flags_init, final_flags)

    except UcError as e:
        logging.warning("Managed error: %s - at code %s" , e, str(g.hex).encode('hex'))

        return (rv_pairs, None, rand_stack, sp_init, address_written, address_read, None, None)
    

def do_analysis(g):
    ###
    #print g
    #for i in Arch.md.disasm(g.hex, g.address):
    #    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    ###

    #init Arch for multiprocessing
    Arch.init(g.arch)

    typed_gadgets = []

    (rv_pairs, final_values, rand_stack, sp_init,
        address_written, address_read, flags_init, final_flags) = emulate(g)

    #emulate two times for memory operations
    (rv_pairs2, final_values2, rand_stack2, sp_init2,
        address_written2, address_read2, flags_init2, final_flags2) = emulate(g)

    if final_values is None or final_values2 is None:
        return []
    #check modified regs
    modified_regs = set()
    for r in Arch.regs_no_sp:
        if rv_pairs[r] != final_values[r]:
            modified_regs.add(r)
    # must be hashable
    g.modified_regs = frozenset(modified_regs)
    #print g.modified_regs
    #TODO: xchg    eax, esp
    # ret not executed in unicorn
    g.stack_fix = final_values[Arch.Registers_sp] - \
        sp_init + (Arch.ARCH_BITS / 8) + g.retn
    #also adjust stack fix as side effect
    typed_gadgets += checkOpEspGadget(
        rv_pairs, final_values, rv_pairs2, final_values2, g)
    if g.stack_fix < 4 or g.stack_fix > 0x1000:
        return []
    typed_gadgets += checkLoadConstGadget(
        rv_pairs, rand_stack, final_values, g)
    typed_gadgets += checkCopyRegGadget(
        rv_pairs, rand_stack, final_values, g)
    typed_gadgets += checkBinOpGadget(
        rv_pairs, rand_stack, final_values, g)
    typed_gadgets += checkLahfGadget(
        flags_init, final_flags, final_values, g)
    typed_gadgets += checkReadMemGadget(
        rv_pairs, final_values, address_read, rv_pairs2, final_values2, address_read2, g)
    typed_gadgets += checkWriteMemGadget(
        rv_pairs, address_written, rv_pairs2, address_written2, g)
    typed_gadgets += checkReadMemOpGadget(
        rv_pairs, final_values, address_read, rv_pairs2, final_values2, address_read2, g)
    typed_gadgets += checkWriteMemOpGadget(
        rv_pairs, address_read, address_written, rv_pairs2, address_read2, address_written2, g)
    return typed_gadgets

class GadgetsCollector(object):
    def __init__(self, filename):
        self._filename =  filename

    def collect(self, do_filter_unsafe=True):
        print 'Collecting...'
        logging.info("Starting Collection phase")
        options = {'color': False,     # if gadgets are printed, use colored output: default: False
                   'badbytes': '',   # bad bytes which should not be in addresses or ropchains; default: ''
                   'all': False,      # Show all gadgets, this means to not remove double gadgets; default: False
                   'inst_count': 6,   # Number of instructions in a gadget; default: 6
                   'type': 'rop',     # rop, jop, sys, all; default: all
                   'detailed': True}  # if gadgets are printed, use detailed output; default: False
        rs = RopperService(options)
        rs.addFile(self._filename)
        rs.loadGadgetsFor(name=self._filename)
        ropper_gadgets = rs.getFileFor(name=self._filename).gadgets
        # set architecture!!
        Arch.init(str(rs.getFileFor(name=self._filename).arch))
        gadgets = []
        for g in ropper_gadgets:
            address = g._lines[0][0] + g.imageBase
            address_end = g._lines[-1][0] + g.imageBase
            hex_bytes = g._bytes
            #check ret type
            ret = Arch.md.disasm(str(hex_bytes[address_end - address:]), 0x0, count = 1).next()
            if ret.id != X86_INS_RET:
                continue
            if ret.operands:
                retn = ret.operands[0].value.imm
            else:
                retn = 0
            if retn < MAX_RETN:
                gadgets.append(Gadget(str(hex_bytes), address = address, address_end = address_end, retn=retn, arch=Arch.ARCH_BITS))
        if do_filter_unsafe:
            return filter_unsafe(gadgets)
        else:
            return gadgets
    
    def analyze(self):
        safe_gadgets = self.collect(do_filter_unsafe=True)
        print 'Analyzing...'
        logging.info("Starting Analysis phase")
        typed_gadgets = []

        # tqdm: progressbar wrapper
        
        pool = Pool()
        '''
        for g in tqdm(safe_gadgets):
            typed_gadgets.append(do_analysis(g))
        '''
        for res in tqdm(pool.imap_unordered(do_analysis, safe_gadgets), total=len(safe_gadgets)):
            typed_gadgets += res
        pool.close()
        pool.join()
        
        print 'Found %d different typed gadgets' % len(typed_gadgets)
        logging.info('Found %d different typed gadgets', len(typed_gadgets))
        return typed_gadgets
        
   




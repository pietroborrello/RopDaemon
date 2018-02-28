#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
import random
from struct import pack, unpack
from itertools import permutations, combinations
from ropper import RopperService
from Gadget import Gadget, Registers, Operations, Types
from Gadget import *
import capstone
from capstone.x86 import *
from unicorn import *
from unicorn.x86_const import *

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# memory address where emulation starts
ADDRESS = 0x1000000

ARCH_BITS = 32
PAGE_SIZE = 4 * 1024
PACK_VALUE = 'I'
MAX_INT = 0xFFFFFFFF
FLAGS_MASK = 0xd5

regs = {Registers.EAX:  UC_X86_REG_EAX, Registers.EBX:  UC_X86_REG_EBX, 
        Registers.ECX:  UC_X86_REG_ECX, Registers.EDX:  UC_X86_REG_EDX, 
        Registers.ESI:  UC_X86_REG_ESI, Registers.EDI:  UC_X86_REG_EDI, 
        Registers.EBP:  UC_X86_REG_EBP, Registers.ESP:  UC_X86_REG_ESP}

regs_no_esp = {Registers.EAX:  UC_X86_REG_EAX, Registers.EBX:  UC_X86_REG_EBX,
               Registers.ECX:  UC_X86_REG_ECX, Registers.EDX:  UC_X86_REG_EDX,
               Registers.ESI:  UC_X86_REG_ESI, Registers.EDI:  UC_X86_REG_EDI,
               Registers.EBP:  UC_X86_REG_EBP}

FLAGS_REG = UC_X86_REG_EFLAGS

def rand():
    r = random.getrandbits(30)
    while r == 0:
        r = random.getrandbits(30)
    return r

def filter_unsafe(gadgets):
    safe_gadgets = []
    unsafe_classes = [X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_INT]
    for g in gadgets:
        unsafe = False
        for i in md.disasm(g.hex, g.address):
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
                if off <= gadget.stack_fix - (ARCH_BITS/8):
                    result.append(LoadConst_Gadget(r, off*(ARCH_BITS/8), gadget))
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
        return (a + b) & MAX_INT
    elif op == Operations.SUB:
        return (a - b) & MAX_INT
    elif op == Operations.MUL:
        return (a * b) & MAX_INT
    elif op == Operations.DIV:
        return (a // b) & MAX_INT
    elif op == Operations.XOR:
        return (a ^ b) & MAX_INT
    elif op == Operations.OR:
        return (a | b) & MAX_INT
    elif op == Operations.AND:
        return (a & b) & MAX_INT


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
            for src1, src2 in combinations(regs, 2):
                op_res = compute_operation(
                    init_regs[src1], op, init_regs[src2])
                for dest in [r for r in final_state if final_state[r] == op_res and r in gadget.modified_regs]:
                    result.append(BinOp_Gadget(dest, src1, op, src2, gadget))
        else:
            for src1, src2 in permutations(regs, 2):
                op_res = compute_operation(
                    init_regs[src1], op, init_regs[src2])
                # if DIV, only valid EAX=EAX/src2, TODO: not op_res == 0 may miss some DIV gadgets
                if op == Operations.DIV and (op_res == 0 or src1 != Registers.EAX):
                        continue
                for dest in [r for r in final_state if final_state[r] == op_res and r in gadget.modified_regs]:
                    result.append(BinOp_Gadget(dest, src1, op, src2, gadget))

    return result

#TODO: uneffective
def hook_err(uc, int_num, user_data):
    print 'ERROR: interrupt %x' % int_num
    if int_num==0: #div fault
        #set EDX to zero since EDX:EAX / reg didn't fit in 32 bits
        for r in regs:
            print 'ERROR: %s 0x%x' % (r.name, uc.reg_read(regs[r]))
        uc.reg_write(UC_X86_REG_EDX, 0x0)
    return True

# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    #memory access not aligned, so map two pages to be sure
    uc.mem_map((address // PAGE_SIZE) * PAGE_SIZE, 2 * PAGE_SIZE)
    return True
    '''if access == UC_MEM_WRITE_UNMAPPED:
        print("MEM INV WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        # map this memory in with page size, aligned
        uc.mem_map((address // PAGE_SIZE)*PAGE_SIZE , PAGE_SIZE)
        print('MEM MAPPED 0x%x' % ((address // PAGE_SIZE) * PAGE_SIZE))
        # return True to indicate we want to continue emulation
        return True
    else: #access == UC_MEM_READ_UNMAPPED:
        print("MEM INV READ at 0x%x, data size = %u" % (address, size))
        # map this memory in with page size, aligned
        uc.mem_map((address // PAGE_SIZE) * PAGE_SIZE, PAGE_SIZE)
        print('MEM MAPPED 0x%x' % ((address // PAGE_SIZE) * PAGE_SIZE))
        return True'''


# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    address_written = user_data[0]
    address_read = user_data[1]
    if access == UC_MEM_WRITE:
        print("MEM WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        address_written[address] = value
    else:   # READ
        #value = unpack(PACK_VALUE, uc.mem_read(address, ARCH_BITS/8))[0]
        #check if previously written or stack
        if address not in address_written: #initialize if never written
            value = rand()
            uc.mem_write(address, pack(PACK_VALUE, value))
        else:
            #TODO: ignored real read size, only full registers
            value = unpack(PACK_VALUE, uc.mem_read(address, ARCH_BITS/8))[0]
        address_read[address] = value
        print("MEM READ at 0x%x, data size = %u, value = 0x%x" % (address, size, value))


def checkReadMemGadget(
    rv_pairs1, final_values1, address_read1, rv_pairs2, final_values2, address_read2, gadget):
    result = []
    for dest in gadget.modified_regs:
        possible = set()
        for addr in [addr for addr in address_read1 if address_read1[addr] == final_values1[dest]]:
            for addr_reg in rv_pairs1:
                if addr_reg is not Registers.ESP:
                    offset = (addr - rv_pairs1[addr_reg]) & MAX_INT
                    possible.add((dest, addr_reg, offset))
        for addr in [addr for addr in address_read2 if address_read2[addr] == final_values2[dest]]:
            for addr_reg in rv_pairs2:
                if addr_reg is not Registers.ESP:
                    offset = (addr - rv_pairs2[addr_reg]) & MAX_INT
                    if (dest, addr_reg, offset) in possible:
                        result.append(ReadMem_Gadget(dest, addr_reg, offset, gadget))
    return result


def checkWriteMemGadget(
        rv_pairs1, address_written1, rv_pairs2, address_written2, gadget):
    result = []
    for src in regs_no_esp:
        possible = set()
        for addr in [addr for addr in address_written1 if address_written1[addr] == rv_pairs1[src]]:
            for addr_reg in rv_pairs1:
                if addr_reg is not Registers.ESP:
                    offset = (addr - rv_pairs1[addr_reg]) & MAX_INT
                    possible.add((addr_reg, offset, src))
        for addr in [addr for addr in address_written2 if address_written2[addr] == rv_pairs2[src]]:
            for addr_reg in rv_pairs2:
                if addr_reg is not Registers.ESP:
                    offset = (addr - rv_pairs2[addr_reg]) & MAX_INT
                    if (addr_reg, offset, src) in possible:
                        result.append(WriteMem_Gadget(addr_reg, offset, src, gadget))
    return result

def checkReadMemOpGadget(
    rv_pairs1, final_values1, address_read1, rv_pairs2, final_values2, address_read2, gadget):
    result = []
    for dest in gadget.modified_regs:
        possible = set()
        for op in Operations:
            for addr in address_read1:
                if compute_operation(address_read1[addr], op, rv_pairs1[dest]) == final_values1[dest]:
                    for addr_reg in rv_pairs1:
                        if addr_reg is not Registers.ESP:
                            offset = (addr - rv_pairs1[addr_reg]) & MAX_INT
                            possible.add((dest, addr_reg, offset))
            for addr in address_read2:
                if compute_operation(address_read2[addr], op, rv_pairs2[dest]) == final_values2[dest]:
                    for addr_reg in rv_pairs2:
                        if addr_reg is not Registers.ESP:
                            offset = (addr - rv_pairs2[addr_reg]) & MAX_INT
                            if (dest, addr_reg, offset) in possible:
                                result.append(ReadMemOp_Gadget(dest, op, addr_reg, offset, gadget))
    return result

# [addr_reg + offset] OP= src
def checkWriteMemOpGadget(
        rv_pairs1, address_read1, address_written1, rv_pairs2, address_read2, address_written2, gadget):
    result = []
    for src in regs_no_esp:
        possible = set()
        for op in Operations:
            for addr in address_written1:
                if addr in address_read1 and address_written1[addr] == compute_operation(address_read1[addr], op, rv_pairs1[src]):
                    for addr_reg in rv_pairs1:
                        if addr_reg is not Registers.ESP:
                            offset = (addr - rv_pairs1[addr_reg]) & MAX_INT
                            possible.add((addr_reg, offset, src))
            for addr in address_written2:
                if addr in address_read2 and address_written2[addr] == compute_operation(address_read2[addr], op, rv_pairs2[src]):
                    for addr_reg in rv_pairs2:
                        if addr_reg is not Registers.ESP:
                            offset = (addr - rv_pairs2[addr_reg]) & MAX_INT
                            if (addr_reg, offset, src) in possible:
                                result.append(WriteMemOp_Gadget(addr_reg, offset, op, src, gadget))
    return result

#AH: = SF: ZF: xx: AF: xx: PF: 1: CF
# xx - unknown
# mask: 0xd5
# 2nd youngest bit of EFLAGS is set to 1 (reserved bit)
def checkLahfGadget(flags_init, final_flags, final_state, gadget):
    if flags_init == final_flags and Registers.EAX in gadget.modified_regs:
        ah = ((final_state[Registers.EAX] >> 8) & FLAGS_MASK) | 2
        if ah == (final_flags & FLAGS_MASK) | 2 :
            return [Lahf_Gadget(gadget)]
    return []


def checkOpEspGadget(init_regs1, final_state1, init_regs2, final_state2, gadget):
    # diff := stack_fix +/- register
    diff1 = final_state1[Registers.ESP] - init_regs1[Registers.ESP]
    diff2 = final_state2[Registers.ESP] - init_regs2[Registers.ESP]

    for r in regs_no_esp:
        stack_fix1 = compute_operation(diff1, Operations.SUB, init_regs1[r])
        stack_fix2 = compute_operation(diff2, Operations.SUB, init_regs2[r])
        if stack_fix1 == stack_fix2 and stack_fix1 + (ARCH_BITS / 8) > 0 and stack_fix1 + (ARCH_BITS / 8)< 0x1000:
            gadget.stack_fix = stack_fix1 + (ARCH_BITS / 8)
            return [OpEsp_Gadget(r, Operations.ADD, gadget)]

    return []

def emulate(g): #gadget g
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        esp_init = ADDRESS + 0x112233
        rv_pairs = {}
        for r in regs_no_esp:
            rv_pairs[r] = rand()
        rv_pairs[Registers.ESP] = esp_init
        rand_stack = []
        address_written = {}
        address_read = {}
        for i in range(8):
            value = rand()
            rand_stack.append(value)
            address_written[esp_init + (ARCH_BITS/8)*i] = value
        flags_init = rand() & FLAGS_MASK

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, g.hex)
        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, esp_init)
        #init registers with random values
        for r in regs_no_esp:
            mu.reg_write(regs[r], rv_pairs[r])
            #print r, hex(rv_pairs[r])
        mu.reg_write(FLAGS_REG, flags_init)
        #write stack
        for i in range(len(rand_stack)):
            mu.mem_write(mu.reg_read(UC_X86_REG_ESP) +
                            (ARCH_BITS / 8) * i, pack(PACK_VALUE, rand_stack[i]))
            #print hex(rand_stack[i])

        # intercept invalid memory events
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        #intercept CPU errors (probably due to div)
        mu.hook_add(UC_HOOK_INTR, hook_err, user_data = ADDRESS + len(g.hex) - 1)
        # tracing all memory READ & WRITE access
        user_data = (address_written, address_read)
        mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ,
                    hook_mem_access, user_data=user_data)
        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(g.hex) - 1)

        final_values = {}
        for r in regs:
            final_values[r] = mu.reg_read(regs[r])
        final_flags = mu.reg_read(FLAGS_REG)
        return (rv_pairs, final_values, rand_stack, esp_init, address_written, address_read, flags_init, final_flags)

    except UcError as e:
        print("ERROR: %s" % e)
        return (rv_pairs, None, rand_stack, esp_init, address_written, address_read, None, None)
    

class GadgetsCollector(object):
    def __init__(self, filename):
        self._filename =  filename
        self._binary = None

    def collect(self):
        options = {'color': False,     # if gadgets are printed, use colored output: default: False
                   'badbytes': '',   # bad bytes which should not be in addresses or ropchains; default: ''
                   'all': False,      # Show all gadgets, this means to not remove double gadgets; default: False
                   'inst_count': 6,   # Number of instructions in a gadget; default: 6
                   'type': 'rop',     # rop, jop, sys, all; default: all
                   'detailed': True}  # if gadgets are printed, use detailed output; default: False
        rs = RopperService(options)
        rs.addFile(self._filename)
        #TODO: architecture set only x86
        rs.setArchitectureFor(name=self._filename, arch='x86')
        rs.loadGadgetsFor(name=self._filename)
        ropper_gadgets = rs.getFileFor(name=self._filename).gadgets
        gadgets = []
        for g in ropper_gadgets:
            address = g._lines[0][0] + g.imageBase
            address_end = g._lines[-1][0] + g.imageBase + 1
            hex_bytes = g._bytes
            gadgets.append(Gadget(str(hex_bytes), address = address, address_end = address_end))
        return gadgets
    
    def analyze(self):
        gadgets = self.collect()
        safe_gadgets = filter_unsafe(gadgets)
        typed_gadgets = {}
        for t in Types:
            typed_gadgets[t] = []

        for g in safe_gadgets:
            ###
            print g
            for i in md.disasm(g.hex, g.address):
                print("0x%x:\t%s\t%s" %
                      (i.address, i.mnemonic, i.op_str))
            ###
            (rv_pairs, final_values, rand_stack, esp_init,
             address_written, address_read, flags_init, final_flags) = emulate(g)

            #emulate two times for memory operations
            (rv_pairs2, final_values2, rand_stack2, esp_init2,
             address_written2, address_read2, flags_init2, final_flags2) = emulate(g)

            if final_values is None or final_values2 is None:
                continue
            #check modified regs
            g.modified_regs = []
            for r in regs_no_esp:
                if rv_pairs[r] != final_values[r]:
                    g.modified_regs.append(r)
            #print g.modified_regs
            #TODO: xchg    eax, esp
            # ret not executed in unicorn
            g.stack_fix = final_values[Registers.ESP] - \
                esp_init + (ARCH_BITS / 8)

            #also adjust stack fix as side effect
            typed_gadgets[Types.OpEsp] += checkOpEspGadget(
                rv_pairs, final_values, rv_pairs2, final_values2, g)
            if g.stack_fix < 4 or g.stack_fix > 0x1000:
                continue

            typed_gadgets[Types.LoadConst] += checkLoadConstGadget(
                rv_pairs, rand_stack, final_values, g)
            typed_gadgets[Types.CopyReg] += checkCopyRegGadget(
                rv_pairs, rand_stack, final_values, g)
            typed_gadgets[Types.BinOp] += checkBinOpGadget(
                rv_pairs, rand_stack, final_values, g)
            typed_gadgets[Types.Lahf] += checkLahfGadget(
                flags_init, final_flags, final_values, g)
            typed_gadgets[Types.ReadMem] += checkReadMemGadget(
                rv_pairs, final_values, address_read, rv_pairs2, final_values2, address_read2, g)
            typed_gadgets[Types.WriteMem] += checkWriteMemGadget(
                rv_pairs, address_written, rv_pairs2, address_written2, g)
            typed_gadgets[Types.ReadMemOp] += checkReadMemOpGadget(
                rv_pairs, final_values, address_read, rv_pairs2, final_values2, address_read2, g)
            typed_gadgets[Types.WriteMemOp] += checkWriteMemOpGadget(
                rv_pairs, address_read, address_written, rv_pairs2, address_read2, address_written2, g)
            

        for t in typed_gadgets:
            for g in typed_gadgets[t]:
                print g
        
   




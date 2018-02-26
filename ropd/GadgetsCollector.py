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

regs = {Registers.EAX:  UC_X86_REG_EAX, Registers.EBX:  UC_X86_REG_EBX, 
        Registers.ECX:  UC_X86_REG_ECX, Registers.EDX:  UC_X86_REG_EDX, 
        Registers.ESI:  UC_X86_REG_ESI, Registers.EDI:  UC_X86_REG_EDI, 
        Registers.EBP:  UC_X86_REG_EBP, Registers.ESP:  UC_X86_REG_ESP}

regs_no_esp = {Registers.EAX:  UC_X86_REG_EAX, Registers.EBX:  UC_X86_REG_EBX,
               Registers.ECX:  UC_X86_REG_ECX, Registers.EDX:  UC_X86_REG_EDX,
               Registers.ESI:  UC_X86_REG_ESI, Registers.EDI:  UC_X86_REG_EDI,
               Registers.EBP:  UC_X86_REG_EBP}

def rand():
    return random.getrandbits(30)

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
                result.append(LoadConst_Gadget(r, off, gadget))
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
        return (a + b) & 0xFFFFFFFF
    elif op == Operations.SUB:
        return (a - b) & 0xFFFFFFFF
    elif op == Operations.MUL:
        return (a * b) & 0xFFFFFFFF
    elif op == Operations.DIV:
        return (a // b) & 0xFFFFFFFF
    elif op == Operations.XOR:
        return (a ^ b) & 0xFFFFFFFF
    elif op == Operations.OR:
        return (a | b) & 0xFFFFFFFF
    elif op == Operations.AND:
        return (a & b) & 0xFFFFFFFF


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
            #init unicorn enigne to clean memory space
            try:
                mu = Uc(UC_ARCH_X86, UC_MODE_32)
                esp_init = ADDRESS + 0x112233
                rv_pairs = {}
                for r in regs_no_esp:
                    rv_pairs[r] = rand()
                rv_pairs[Registers.ESP] = esp_init
                rand_stack = []
                for i in range(8):
                    rand_stack.append(rand())

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
                #write stack
                for i in range(len(rand_stack)):
                    mu.mem_write(mu.reg_read(UC_X86_REG_ESP) + (ARCH_BITS/8)*i, pack('I', rand_stack[i]))
                    #print hex(rand_stack[i])
                
                # emulate machine code in infinite time
                mu.emu_start(ADDRESS, ADDRESS + len(g.hex) - 1)

                final_values = {}
                for r in regs:
                    final_values[r] = mu.reg_read(regs[r])

                #check modified regs
                g.modified_regs = []
                for r in regs_no_esp:
                    if rv_pairs[r] != final_values[r]:
                        g.modified_regs.append(r)
                #print g.modified_regs
                #TODO: xchg    eax, esp
                g.stack_fix = final_values[Registers.ESP] - esp_init + (ARCH_BITS/8) #ret not executed in unicorn
                if g.stack_fix <= 0 or g.stack_fix > 64:
                    continue
                
                typed_gadgets[Types.LoadConst] += checkLoadConstGadget(
                    rv_pairs, rand_stack, final_values, g)
                typed_gadgets[Types.CopyReg] += checkCopyRegGadget(
                    rv_pairs, rand_stack, final_values, g)
                typed_gadgets[Types.BinOp] += checkBinOpGadget(
                    rv_pairs, rand_stack, final_values, g)
            except UcError as e:
                print("ERROR: %s" % e)

        for t in typed_gadgets:
            for g in typed_gadgets[t]:
                print g
        
   




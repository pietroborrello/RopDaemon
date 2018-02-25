#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
from enum import Enum


class Gadget(object):
    def __init__(self, hex, address=None, address_end=None, modified_regs=None, stack_fix=None):
        self.hex = hex
        self.address = address
        self.address_end = address_end
        self.modified_regs = modified_regs
        self.stack_fix = stack_fix

    def __str__(self):
        return 'Gadget(%s, %s, %s, %s, %s)' % (str(self.hex).encode('hex'), hex(self.address), hex(self.address_end), self.modified_regs, self.stack_fix)


#GADGET TYPES
'''
type reg = EAX | EBX | ECX | EDX | ESI | EDI | EBP | ESP
type op = ADD | SUB | MUL | DIV | XOR | OR | AND
type gadget =  
            | LoadConst of reg * int (* reg, stack offset *)
            | CopyReg of reg * reg (* dst reg = src reg *)
            | BinOp of reg * reg * op * reg (* dst reg = src1 OP src2 *)
            | ReadMem of reg * reg * int32 (* dst = [addr_reg + offset] *)
            | WriteMem of reg * int32 * reg (* [addr_reg + offset] = src *)
            | ReadMemOp of reg * op * reg * int32 (* dst OP= [addr_reg + offset] *)
            | WriteMemOp of reg * int32 * op * reg (* [addr_reg + offset] OP= src_reg *)
            | Lahf 
            | OpEsp of op * reg * int (* esp = esp op reg, where op=+/-, sf =
                stack_fix *)
                '''

Registers = Enum('Registers', 'EAX EBX ECX EDX ESI EDI EBP ESP')
Operations = Enum('Operations', 'ADD SUB MUL DIV XOR OR AND')
Types = Enum(
    'Types', 'LoadConst CopyReg  BinOp ReadMem WriteMem ReadMemOp WriteMemOp Lahf OpEsp')


class LoadConst_Gadget(Gadget): # reg = const (at offset from esp)
    def __init__(self, register, offset, gadget):
        self.register = register
        self.offset = offset
        super(LoadConst_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)

    def __str__(self):
        mod = []
        for r in self.modified_regs:
            mod.append(r.name)
        return 'LoadConst_Gadget(%s, %s)(%s, %s, %s, %s, %s)' % (self.register.name, hex(self.offset), str(self.hex).encode('hex'), hex(self.address), hex(self.address_end), mod, self.stack_fix)


class CopyReg_Gadget(Gadget):  # dest = src
    def __init__(self, dest, src, gadget):
        self.dest = dest
        self.src = src
        super(CopyReg_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)


class BinOp_Gadget(Gadget):  # dest = src1 OP src2
    def __init__(self, dest, src1, op, src2):
        self.dest = dest
        self.src1 = src1
        self.op = op
        self.src2 = src2
        super(BinOp_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)


class ReadMem_Gadget(Gadget):  # dest = [addr_reg + offset]
    def __init__(self, dest, addr_reg, offset):
        self.dest = dest
        self.addr_reg = addr_reg
        self.offset = offset
        super(ReadMem_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)


class WriteMem_Gadget(Gadget):  # [addr_reg + offset] = src
    def __init__(self, addr_reg, offset, src):
        self.src = src
        self.addr_reg = addr_reg
        self.offset = offset
        super(WriteMem_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)                                    


class ReadMemOp_Gadget(Gadget):  # dest OP= [addr_reg + offset]
    def __init__(self, dest, op, addr_reg, offset):
        self.dest = dest
        self.op = op
        self.addr_reg = addr_reg
        self.offset = offset
        super(ReadMemOp_Gadget, self).__init__(gadget.hex, gadget.address,
                                             gadget.address_end, gadget.modified_regs, gadget.stack_fix)


class WriteMemOp_Gadget(Gadget):  # [addr_reg + offset] OP= src
    def __init__(self, addr_reg, offset, op, src):
        self.src = src
        self.op = op 
        self.addr_reg = addr_reg
        self.offset = offset
        super(WriteMemOp_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)

class Lahf_Gadget(Gadget): #load FLAGS to AH
    def __init__(gadget):
        super(Lahf_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)


class OpEsp_Gadget(Gadget):  # esp=esp op reg
    def __init__(self, register, offset, fix, gadget):
        self.register = register
        self.offset = offset
        self.fix = fix
        super(OpEsp_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix)





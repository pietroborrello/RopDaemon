#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
from enum import Enum
import Arch
import capstone

md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md64.detail = True

md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md32.detail = True


class Gadget(object):
    def __init__(self, hex, address=None, address_end=None, modified_regs=None, stack_fix=None, retn=None, arch=None, mem=None):
        self.hex = hex
        self.address = address
        self.address_end = address_end
        self.modified_regs = modified_regs
        # (frozenset(mem), simple_access)
        self.mem = mem
        self.stack_fix = stack_fix
        self.retn = retn
        self.arch = arch

    def __str__(self):
        mod = []
        for r in self.modified_regs:
            mod.append(r.name)
        mem = []
        for r in self.mem[0]:
            mem.append(r.name)
        simple_accesses = self.mem[1]
        return '(%s, %s, %s, mod_regs = %s, mem = %s %s, %d)' % (str(self.hex).encode('hex'), hex(self.address), hex(self.address_end), mod, mem, simple_accesses, self.stack_fix)
    
    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__
    
    def __ne__(self, other):
        """Overrides the default implementation (unnecessary in Python 3)"""
        return not self.__eq__(other)

    def __hash__(self):
        """Overrides the default implementation"""
        return hash(tuple(sorted(self.__dict__.items())))
    
    def dump(self):
        if self.arch == Arch.ARCH_32:
            md = md32
        else:
            md = md64
        ris = ''
        for i in md.disasm(self.hex, self.address):
            ris += ("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))
        return ris


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

Operations = Enum('Operations', 'ADD SUB MUL DIV XOR OR AND')
Types = Enum(
    'Types', 'LoadConst CopyReg  BinOp ReadMem WriteMem ReadMemOp WriteMemOp Lahf OpEsp')

def hex(s):
    return '0x' + format(s, 'x')


class LoadConst_Gadget(Gadget): # reg = const (at offset from esp)
    def __init__(self, register, offset, gadget):
        self.register = register
        self.offset = offset
        super(LoadConst_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)

    def __str__(self):
        return 'LoadConst_Gadget(%s, %s)' % (self.register.name, hex(self.offset)) + super(LoadConst_Gadget, self).__str__()


class CopyReg_Gadget(Gadget):  # dest = src
    def __init__(self, dest, src, gadget):
        self.dest = dest
        self.src = src
        super(CopyReg_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)

    def __str__(self):
        return 'CopyReg_Gadget(%s, %s)' % (self.dest.name, self.src.name) + super(CopyReg_Gadget, self).__str__()

class BinOp_Gadget(Gadget):  # dest = src1 OP src2
    def __init__(self, dest, src1, op, src2, gadget):
        self.dest = dest
        self.src1 = src1
        self.op = op
        self.src2 = src2
        super(BinOp_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)

    def __str__(self):
        op = self.op
        if op == Operations.ADD:
            op = '+'
        elif op == Operations.SUB:
            op = '-'
        elif op == Operations.MUL:
            op = '*'
        elif op == Operations.DIV:
            op = '/'
        elif op == Operations.XOR:
            op = '^'
        elif op == Operations.OR:
            op = '|'
        elif op == Operations.AND:
            op = '&'
        return 'BinOp_Gadget(%s, %s, %s, %s)' % (self.dest.name, self.src1.name, op, self.src2.name) + super(BinOp_Gadget, self).__str__()

class ReadMem_Gadget(Gadget):  # dest = [addr_reg + offset]
    def __init__(self, dest, addr_reg, offset, gadget):
        self.dest = dest
        self.addr_reg = addr_reg
        self.offset = offset
        super(ReadMem_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)

    def __str__(self):
        return 'ReadMem_Gadget(%s = [%s + %s])' % (self.dest.name, self.addr_reg.name, hex(self.offset)) + super(ReadMem_Gadget, self).__str__()


class WriteMem_Gadget(Gadget):  # [addr_reg + offset] = src
    def __init__(self, addr_reg, offset, src, gadget):
        self.src = src
        self.addr_reg = addr_reg
        self.offset = offset
        super(WriteMem_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)  

    def __str__(self):
        return 'WriteMem_Gadget([%s + %s] = %s)' % (self.addr_reg.name, hex(self.offset), self.src.name) + super(WriteMem_Gadget, self).__str__()


class ReadMemOp_Gadget(Gadget):  # dest OP= [addr_reg + offset]
    def __init__(self, dest, op, addr_reg, offset, gadget):
        self.dest = dest
        self.op = op
        self.addr_reg = addr_reg
        self.offset = offset
        super(ReadMemOp_Gadget, self).__init__(gadget.hex, gadget.address,
                                             gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)
    def __str__(self):
        op = self.op
        if op == Operations.ADD:
            op = '+'
        elif op == Operations.SUB:
            op = '-'
        elif op == Operations.MUL:
            op = '*'
        elif op == Operations.DIV:
            op = '/'
        elif op == Operations.XOR:
            op = '^'
        elif op == Operations.OR:
            op = '|'
        elif op == Operations.AND:
            op = '&'
        return 'ReadMemOp_Gadget(%s %s= [%s + %s])' % (self.dest.name, op, self.addr_reg.name, hex(self.offset)) + super(ReadMemOp_Gadget, self).__str__()


class WriteMemOp_Gadget(Gadget):  # [addr_reg + offset] OP= src
    def __init__(self, addr_reg, offset, op, src, gadget):
        self.src = src
        self.op = op 
        self.addr_reg = addr_reg
        self.offset = offset
        super(WriteMemOp_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)
    def __str__(self):
        op = self.op
        if op == Operations.ADD:
            op = '+'
        elif op == Operations.SUB:
            op = '-'
        elif op == Operations.MUL:
            op = '*'
        elif op == Operations.DIV:
            op = '/'
        elif op == Operations.XOR:
            op = '^'
        elif op == Operations.OR:
            op = '|'
        elif op == Operations.AND:
            op = '&'
        return 'WriteMemOp_Gadget([%s + %s] %s= %s)' % (self.addr_reg.name, hex(self.offset), op, self.src.name) + super(WriteMemOp_Gadget, self).__str__()

#AH: = SF: ZF: xx: AF: xx: PF: 1: CF
# xx - unknown
# mask: 0xd5
# 2nd youngest bit of EFLAGS is set to 1 (reserved bit)
class Lahf_Gadget(Gadget): #load FLAGS to AH
    def __init__(self, gadget):
        super(Lahf_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)

    def __str__(self):
        return 'Lahf_Gadget' + super(Lahf_Gadget, self).__str__()

class OpEsp_Gadget(Gadget):  # esp=esp op reg
    def __init__(self, register, operation, gadget):
        self.register = register
        self.operation = operation
        super(OpEsp_Gadget, self).__init__(gadget.hex, gadget.address,
                                               gadget.address_end, gadget.modified_regs, gadget.stack_fix, gadget.retn, gadget.arch, gadget.mem)

    def __str__(self):
        op = self.operation
        if op == Operations.ADD:
            op = '+'
        elif op == Operations.SUB:
            op = '-'
        return 'OpEsp_Gadget(%s, %s)' % (op, self.register.name) + super(OpEsp_Gadget, self).__str__()



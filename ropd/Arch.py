#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
import random
from enum import Enum
from struct import pack, unpack
from itertools import permutations, combinations
import capstone
from capstone.x86 import *
from unicorn import *
from unicorn.x86_const import *
import logging

ARCH_32 = 32
ARCH_64 = 64
STACK_CELLS = 16
md = None
Registers = None
Registers_sp = None
Registers_a = None
Registers_d = None

ARCH_BITS = None
PAGE_SIZE = None
PACK_VALUE = None
MAX_INT = None

regs = None
regs_no_sp  = None
FLAGS_REG = None
IP_REG = None
UC_MODE = None
RAND_BITS = None

Registers32 = Enum('Registers32', 'eax ebx ecx edx esi edi ebp esp')
Registers64 = Enum('Registers64', 'rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15')
UnknownType = Enum('UnknownType', 'unknown')
MemType = Enum('MemType', 'stack')

def init(arch):
    global md
    global Registers
    global Registers_sp
    global Registers_a
    global Registers_d
    
    global ARCH_BITS
    global PAGE_SIZE 
    global PACK_VALUE
    global MAX_INT

    global regs
    global regs_no_sp 
    global FLAGS_REG
    global IP_REG
    global UC_MODE
    global RAND_BITS

    if arch == ARCH_32 or arch == 'x86':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True

        UC_MODE = UC_MODE_32

        Registers = Registers32
        Registers_sp = Registers.esp
        Registers_a = Registers.eax
        Registers_d = Registers.edx

        ARCH_BITS = 32
        PAGE_SIZE = 4 * 1024
        PACK_VALUE = 'I'
        MAX_INT = 0xFFFFFFFF

        regs = {Registers.eax:  UC_X86_REG_EAX, Registers.ebx:  UC_X86_REG_EBX,        Registers.ecx: UC_X86_REG_ECX, Registers.edx:  UC_X86_REG_EDX, 
                Registers.esi:  UC_X86_REG_ESI, Registers.edi:  UC_X86_REG_EDI,Registers.ebp:  UC_X86_REG_EBP, Registers.esp:  UC_X86_REG_ESP}

        regs_no_sp = {Registers.eax:  UC_X86_REG_EAX, Registers.ebx:  UC_X86_REG_EBX, Registers.ecx:  UC_X86_REG_ECX, Registers.edx:  UC_X86_REG_EDX, Registers.esi:  UC_X86_REG_ESI, Registers.edi:  UC_X86_REG_EDI, Registers.ebp:  UC_X86_REG_EBP}

        FLAGS_REG = UC_X86_REG_EFLAGS
        IP_REG = UC_X86_REG_EIP
        RAND_BITS = 30
        
    elif arch == ARCH_64 or arch == 'x86_64':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        UC_MODE = UC_MODE_64

        Registers = Registers64
        Registers_sp = Registers.rsp
        Registers_a = Registers.rax
        Registers_d = Registers.rdx

        ARCH_BITS = 64
        PAGE_SIZE = 4 * 1024
        PACK_VALUE = 'Q'
        MAX_INT = 0xFFFFFFFFFFFFFFFF

        regs = {Registers.rax:  UC_X86_REG_RAX, Registers.rbx:  UC_X86_REG_RBX,        Registers.rcx: UC_X86_REG_RCX, Registers.rdx:  UC_X86_REG_RDX, 
                Registers.rsi:  UC_X86_REG_RSI, Registers.rdi:  UC_X86_REG_RDI,Registers.rbp:  UC_X86_REG_RBP, Registers.rsp:  UC_X86_REG_RSP,
                Registers.r8:  UC_X86_REG_R8, Registers.r9:  UC_X86_REG_R9,    Registers.r10: UC_X86_REG_R10, Registers.r11:  UC_X86_REG_R11, 
                Registers.r12:  UC_X86_REG_R12, Registers.r13:  UC_X86_REG_R13,Registers.r14:  UC_X86_REG_R14, Registers.r15:  UC_X86_REG_R15}

        regs_no_sp = \
            {Registers.rax:  UC_X86_REG_RAX, Registers.rbx:  UC_X86_REG_RBX,    Registers.rcx: UC_X86_REG_RCX, Registers.rdx:  UC_X86_REG_RDX, 
             Registers.rsi:  UC_X86_REG_RSI, Registers.rdi:  UC_X86_REG_RDI,Registers.rbp:  UC_X86_REG_RBP, Registers.r8:  UC_X86_REG_R8, Registers.r9:  UC_X86_REG_R9, Registers.r10: UC_X86_REG_R10, Registers.r11:  UC_X86_REG_R11,Registers.r12:  UC_X86_REG_R12, Registers.r13:  UC_X86_REG_R13,Registers.r14:  UC_X86_REG_R14, Registers.r15:  UC_X86_REG_R15}

        FLAGS_REG = UC_X86_REG_EFLAGS
        IP_REG = UC_X86_REG_RIP
        RAND_BITS = 46
    else: 
        raise Exception('Not supported Architecture: ' + str(arch))

def rand():
    r = random.getrandbits(RAND_BITS)
    while r == 0:
        r = random.getrandbits(RAND_BITS)
    return r



#!/usr/bin/env python3

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2021, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
from enum import Enum
from . import Arch
from .RopChainKernel import RopChainKernel
from .GadgetBox import GadgetBox


def hex(s):
    if s is None:
        return '0x0'
    return '0x' + format(s, 'x')

class RopChain(object):
    def __init__(self, kernels=[]):
        self.gadget_boxes = []
        self.set_registers = {}
        for kernel in kernels:
            self.gadget_boxes += kernel.gadget_boxes

    def simplify(self):
        set_registers = {reg.name: None for reg in Arch.Registers}
        _simple_boxes = []
        for box in self.gadget_boxes:
            try:
                if(set_registers[box.gadget.dest.name] == box.value):
                    continue
                _simple_boxes.append(box)
            except (AttributeError, KeyError):
                _simple_boxes.append(box)
            

            for reg in box.gadget.modified_regs:
                set_registers[reg.name] = None
            try:
                set_registers[box.gadget.dest.name] = box.value
            except AttributeError:
                pass
        #print (self.dump())
        self.gadget_boxes = _simple_boxes

    def dump(self, dump_values=True):
        ris = ''
        if dump_values:
            values = self.evaluate()
            ris += "# values after the chain:\n"
            for reg in Arch.Registers:
                ris += '# ' + (reg.name + ':').ljust(5, ' ') + \
                    (hex(values[reg.name]) if values[reg.name] is not None else '?') + '\n'
            ris += '\n'

        ris += "IMAGE_BASE =  0x0\n"
        ris += "rebase = lambda x : p" + str(Arch.ARCH_BITS) + "(x + IMAGE_BASE)\n\n"
        ris += "rop = ''"
        for box in self.gadget_boxes:
            ris += "\nrop += rebase(" + hex(box.gadget.address)+ ") # " + box.gadget.disasm()
            for i in range(Arch.ARCH_BITS // 8, box.gadget.stack_fix, Arch.ARCH_BITS // 8):
                ris += "\nrop += p" + str(Arch.ARCH_BITS) + "(" + hex(box.value) + ")"
        return ris

    def evaluate(self):
        set_registers = {reg.name: None for reg in Arch.Registers }
        for box in self.gadget_boxes:
            for reg in box.gadget.modified_regs:
                set_registers[reg.name] = None
            try:
                set_registers[box.gadget.dest.name] = box.value
            except AttributeError:
                pass
        return set_registers
            
    def add(self, gadget, value=None):
        self.gadget_boxes.append(GadgetBox(gadget, value=value))

    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Overrides the default implementation (unnecessary in Python 3)"""
        return not self.__eq__(other)

    def __hash__(self):
        """Overrides the default implementation"""
        return hash(tuple(sorted(self.__dict__.items())))

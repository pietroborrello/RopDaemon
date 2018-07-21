#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
from enum import Enum
import Arch
from GadgetBox import GadgetBox


class RopChainKernel(object):
    def __init__(self, gadget_boxes = []):
        self.gadget_boxes  = gadget_boxes
        self.modified_regs = set()
        for box in gadget_boxes:
            self.modified_regs.update(box.gadget.modified_regs)

    def dest(self):
        try:
            return self.gadget_boxes[-1].gadget.dest
        except:
            return "WriteMem"

    def dump(self):
        ris = ''
        for box in self.gadget_boxes:
            ris += box.dump()
        return ris

    def copy(self):
        ris = RopChainKernel([GadgetBox(box.gadget, value=box.value) for box in self.gadget_boxes])
        return ris
    
    def add(self, gadget, value=None):
        self.gadget_boxes.append(GadgetBox(gadget, value=value))
        self.modified_regs.update(gadget.modified_regs)

    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Overrides the default implementation (unnecessary in Python 3)"""
        return not self.__eq__(other)

    def __hash__(self):
        """Overrides the default implementation"""
        return hash(tuple(sorted(self.__dict__.items())))

#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
import random
from struct import pack, unpack
from itertools import permutations, combinations
from tqdm import *
from Gadget import Gadget, Registers, Operations, Types
from Gadget import *
import sys
import logging

class GadgetsPlayer(object):
    def __init__(self, filename, gadgets):
        self.filename =  filename
        self.gadgets = gadgets

    def stats(self):
        total = 0
        subtotals = {}
        for t in self.gadgets:
            subtotals[t] = 0
            for g in self.gadgets[t]:
                total += 1
                subtotals[t] += 1
        
        per_reg_total_loads = {}

        for g in self.gadgets[Types.LoadConst]:
            if g.register not in per_reg_total_loads:
                per_reg_total_loads[g.register] = 0
            per_reg_total_loads[g.register] += 1

        for t in subtotals:
            print t.name, "%.2f" % (subtotals[t]/float(total) * 100) + '%'
            if t == Types.LoadConst:
                for r in per_reg_total_loads:
                    print "\t", r.name, "%.2f" % (per_reg_total_loads[r]/float(total) * 100) + '%'


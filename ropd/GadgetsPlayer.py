#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
import random
from struct import pack, unpack
from itertools import permutations, combinations, groupby
from tqdm import *
from Gadget import Gadget, Operations, Types
from Gadget import *
import Arch
import networkx as nx
import sys
import logging

def select_best(gadget_list):
        """
        Selects the best gadget between semantically equivalent gadgets, based on dereferenced addresses, modified regs, and stack fix
        """
        best = None
        min_mod = None
        min_addr = None
        min_fix = None
        for g in gadget_list:
            if len(g.mem[0]) < min_addr or min_addr is None:
                best = g 
                min_mod = len(g.modified_regs)
                min_addr = len(g.mem[0])
                min_fix = g.stack_fix
            elif len(g.mem[0]) == min_addr:
                if len(g.modified_regs) < min_mod:
                    best = g
                    min_mod = len(g.modified_regs)
                    min_fix = g.stack_fix
                elif len(g.modified_regs) == min_mod:
                    if g.stack_fix < min_fix:
                        best = g 
                        min_fix = g.stack_fix
        return best

class GadgetsPlayer(object):
    def __init__(self, filename, gadgets):
        self.filename =  filename
        self.gadgets = gadgets
        # assuming all gadget of the same type
        if len(self.gadgets):
            Arch.init(self.gadgets[0].arch)

    def play(self):
        return self.compute_load_sequence()


    def stats(self):
        total = 0
        subtotals = {}
        # TODO: define gadget load analysis
        for g in self.gadgets:
            t = type(g)
            if t not in subtotals: subtotals[t] = 0
            total += 1
            subtotals[t] += 1

        print "Found %d different gadgets" % total
        for t in subtotals:
            print '*', t.__name__, "%.2f" % (subtotals[t]/float(total) * 100) + '%'
            

    def compute_load_sequence(self):
        load_gadgets = {reg : filter(lambda x: isinstance(x, LoadConst_Gadget) and x.dest is reg, self.gadgets) for reg in Arch.Registers}
        load_gadgets = {reg : select_best(load_gadgets[reg]) for reg in load_gadgets}
        for (r, g) in load_gadgets.items():
            if g is not None:
                print r.name
                print g
                print g.dump()

        copy_gadgets = {(dest,src) : list(group) for ((dest,src),group) in groupby(sorted(filter(lambda x: isinstance(x, MovReg_Gadget),self.gadgets), key = lambda g: (g.dest.name, g.src.name)), lambda g: (g.dest, g.src))}
        copy_gadgets = {(dest,src) : select_best(copy_gadgets[(dest,src)]) for (dest,src) in copy_gadgets}
        for ((d,s), g) in copy_gadgets.items():
            if g is not None:
                print d.name, s.name
                print g
                print g.dump()

        loadable_regs = load_gadgets.copy()
        





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
from ChainKernel import ChainKernel
from Chain import Chain
from GadgetBox import GadgetBox
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


def gadget_quality(g):
        return ('unknown' in g.mem[0],
                len(g.mem[0]), len(g.modified_regs), g.stack_fix)



class GadgetsPlayer(object):
    def __init__(self, filename, gadgets):
        self.filename =  filename
        self.gadgets = gadgets
        self.all_load_gadgets = []
        self.best_load_gadgets = []
        self.indipendent_load_gadgets = []
        self.register_values = {'rax': 0x3b,
                                'rdi': 0x4000000, 'rsi': 0x0, 'rdx': 0x0, 'rbx':0x11}
        # assuming all gadget of the same type
        if len(self.gadgets):
            Arch.init(self.gadgets[0].arch)

    def play(self):
        self.compute_load_sequence()
        self.compute_kernels()


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


    def compute_kernels(self):
        kernels = {}
        for reg in self.indipendent_load_gadgets:
            if reg.name in self.register_values:
                kernels[reg] = ChainKernel([GadgetBox(self.indipendent_load_gadgets[reg], value=self.register_values[reg.name])])
        
        missing_regs = [
            reg for reg in self.register_values if Arch.Registers[reg] not in kernels.keys()]

        found_one = True
        while found_one:
            found_one = False
            for reg in missing_regs:
                best_guess = (sorted(filter(lambda g: set(g.mem[0]).issubset(
                    set(kernels.keys())), 
                    self.all_load_gadgets[Arch.Registers[reg]]), key=gadget_quality)+[None])[0]

                if best_guess: 
                    if len(best_guess.mem[0])==1:
                        k = kernels[list(best_guess.mem[0])[0]].copy()
                        k.gadget_boxes[-1].value = 0x4000000
                        k.add(best_guess, value=self.register_values[reg])
                        kernels[Arch.Registers[reg]] = k

                        found_one = True

            missing_regs = [
                reg for reg in self.register_values if Arch.Registers[reg] not in kernels.keys()]
        print '[+] found best guesses'
        print '[+] computing sequence'
        kernels_list = kernels.values()

        while True:
            random.shuffle(kernels_list)
            chain = Chain(kernels_list)
            chain.deduplicate()
            if(chain.evaluate() == self.register_values):
                print chain.dump()
                break
            

            


    
    def compute_load_sequence(self):
        all_load_gadgets = {reg: sorted(filter(lambda x: isinstance(x, LoadConst_Gadget) and x.dest is reg, self.gadgets), key=gadget_quality ) for reg in Arch.Registers}

        best_load_gadgets = {reg : (all_load_gadgets[reg]+[None])[0] for reg in all_load_gadgets}

        # print '---- BEST GUESS ----'
        # for (r, g) in load_gadgets.items():
        #     if g is not None:
        #         print r.name
        #         print g
        #         print g.dump()
    
        indipendent_regs = {}
        for (r, g) in best_load_gadgets.items():
            if g is not None and len(g.modified_regs) == 1 and len(g.mem[0]) == 0:
                indipendent_regs[r] = g
        
        '''print '---- INDEPENDENT REGS ----'
        for (r, g) in indipendent_regs.items():
            print r.name
            print g
            print g.dump()'''

        self.all_load_gadgets = all_load_gadgets
        self.best_load_gadgets = best_load_gadgets
        self.indipendent_load_gadgets = indipendent_regs

        '''
        copy_gadgets = {(dest,src) : list(group) for ((dest,src),group) in groupby(sorted(filter(lambda x: isinstance(x, MovReg_Gadget),self.gadgets), key = lambda g: (g.dest.name, g.src.name)), lambda g: (g.dest, g.src))}

        copy_gadgets = {(dest,src) : (sorted (copy_gadgets[(dest,src)], key=gadget_quality)+[None])[0] for (dest,src) in copy_gadgets}
        
        kernels = {reg: ChainKernel()
                   for reg in indipendent_regs}'''





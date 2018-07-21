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
                len(g.mem[0]), len(g.modified_regs), g.stack_fix, (g.address_end - g.address))



class GadgetsPlayer(object):
    def __init__(self, filename, gadgets):
        self.filename =  filename
        self.gadgets = gadgets
        self.all_load_gadgets = []
        self.best_load_gadgets = []
        self.indipendent_load_gadgets = []
        self.load_kernels = {}
        self.write_kernel = None
        self.kernels = []
        self.chain = None
        self.writable_address = 0x4000000
        #self.register_values = {'rax': 0x3b,'rdi': self.writable_address, 'rsi': 0x0, 'rdx': 0x0}

        self.register_values = {'eax': 0xb,'ebx': self.writable_address, 'ecx': 0x0, 'edx': 0x0}
        
        # assuming all gadget of the same type
        if len(self.gadgets):
            Arch.init(self.gadgets[0].arch)
        for reg in Arch.Registers:
            if reg.name not in self.register_values:
                self.register_values[reg.name] = None

    def play(self):
        self.find_load_gadgets()
        self.compute_load_kernels()
        self.compute_write_kernels()

        syscall_gadget = (sorted(filter(lambda g: isinstance(g, Other_Gadget),  self.gadgets), key=gadget_quality) + [None])[0]

        self.compute_chain()

        if self.chain:
            self.chain.add(syscall_gadget)
            print self.chain.dump()


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


    def compute_load_kernels(self):
        kernels = {}
        for reg in self.indipendent_load_gadgets:
            kernels[reg] = ChainKernel([GadgetBox(self.indipendent_load_gadgets[reg], value=self.register_values[reg.name])])
        
        missing_regs = [
            reg for reg in Arch.Registers if reg not in kernels.keys()]

        found_one = True
        while found_one:
            found_one = False
            for reg in missing_regs:
                best_guess = (sorted(filter(lambda g: set(g.mem[0]).issubset(
                    set(kernels.keys())), 
                    self.all_load_gadgets[reg]), key=gadget_quality)+[None])[0]

                if best_guess: 
                    if len(best_guess.mem[0])==1:
                        k = kernels[list(best_guess.mem[0])[0]].copy()
                        k.gadget_boxes[-1].value = self.writable_address
                        k.add(best_guess, value=self.register_values[reg.name])
                        kernels[reg] = k

                        found_one = True
                    elif len(best_guess.mem[0])==0:
                        kernels[reg] = ChainKernel([GadgetBox(
                            best_guess, value=self.register_values[reg.name])])


            missing_regs = [
                reg for reg in Arch.Registers if reg not in kernels.keys()]
            
        print '[+] found best guesses for:'
        for k in kernels: 
            print k.name

        self.kernels += [kernels[reg]
                         for reg in kernels if self.register_values[reg.name] is not None]
        kernels.values()
        self.load_kernels = kernels


    def compute_write_kernels(self):
        best_write_gadget = (sorted(filter(lambda g: isinstance(g, WriteMem_Gadget) and set([g.addr_reg, g.src]).issubset(
            set(self.load_kernels.keys())),
            self.gadgets), key=gadget_quality) + [None])[0]

        if best_write_gadget:
            if len(best_write_gadget.mem[0]) == 1:
                k1 = self.load_kernels[best_write_gadget.addr_reg].copy()
                k1.gadget_boxes[-1].value = self.writable_address

                k2 = self.load_kernels[best_write_gadget.src].copy()
                # hex(pwn.u64('/bin/sh\x00'))
                k2.gadget_boxes[-1].value = 0x6e69622f#0x68732f6e69622f

                k = ChainKernel([GadgetBox(
                    best_write_gadget, value=None)])

                chain = Chain([k1,k2,k])
                
                tmp_values = {best_write_gadget.addr_reg.name: self.writable_address,
                              best_write_gadget.src.name: 0x6e69622f}#0x68732f6e69622f}
                for reg in Arch.Registers:
                    if reg.name not in tmp_values:
                        tmp_values[reg.name] = None

                if chain.evaluate() != tmp_values:
                    chain = Chain([k2, k1, k])
                if chain.evaluate() != tmp_values:
                    print '[-] Unable to find write memory gadget'
                    return

                self.write_kernel = ChainKernel(chain.gadget_boxes)

        self.kernels.append(self.write_kernel)



    def compute_chain(self):
        print '[+] computing sequence'
        kernels_list = self.kernels

        while True:
            random.shuffle(kernels_list)
            chain = Chain(kernels_list)
            chain.deduplicate()
            _register_values = chain.evaluate()
            
            bad = False
            for reg in _register_values:
                if(_register_values[reg] != self.register_values[reg] and self.register_values[reg] is not None):
                    bad = True
            if bad: 
                print _register_values
                continue
            
            #print chain.dump()
            self.chain = chain
            break
            

    def find_load_gadgets(self):
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





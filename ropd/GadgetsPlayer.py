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
from Gadget import Gadget, Operations, Types
from Gadget import *
import Arch
import networkx as nx
import sys
import logging

class GadgetsPlayer(object):
    def __init__(self, filename, gadgets):
        self.filename =  filename
        self.gadgets = gadgets
        # assuming all gadget of the same type
        for t in self.gadgets:
            if self.gadgets[t]:
                Arch.init(self.gadgets[t][0].arch)


    def stats(self):
        total = 0
        subtotals = {}
        for t in self.gadgets:
            subtotals[t] = 0
            for g in self.gadgets[t]:
                total += 1
                subtotals[t] += 1
        
        per_reg_total_loads = {}
        for r in Arch.Registers:
            per_reg_total_loads[r] = 0

        for g in self.gadgets[Types.LoadConst]:
            per_reg_total_loads[g.register] += 1
        print "Found %d different gadgets" % total
        for t in subtotals:
            print '*', t.name, "%.2f" % (subtotals[t]/float(total) * 100) + '%'
            if t == Types.LoadConst:
                for r in Arch.Registers:
                    print "\t*", r.name, "%.2f" % (per_reg_total_loads[r]/float(total) * 100) + '%'

    def compute_load_sequence(self):
        G = nx.Graph()
        G.add_nodes_from(gadgets[Types.LoadConst])



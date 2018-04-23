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
        if len(self.gadgets):
            Arch.init(self.gadgets[0].arch)


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
        G = nx.Graph()
        G.add_nodes_from(gadgets[Types.LoadConst])




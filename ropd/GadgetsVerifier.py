#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

from binascii import unhexlify, hexlify
import random
from struct import pack, unpack
from itertools import permutations, combinations
import progressbar
from Gadget import Gadget, Registers, Operations, Types
from Gadget import *
import angr


class GadgetsVerifier(object):
    def __init__(self, filename):
        self._filename =  filename
#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"

import logging
logging.basicConfig(filename='ropd.log',filemode='w', format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S',level=logging.DEBUG) 
# mask angr infos
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)
logging.getLogger('ana').setLevel(logging.CRITICAL)

from GadgetsCollector import GadgetsCollector
from GadgetsVerifier import GadgetsVerifier
from GadgetsPlayer import GadgetsPlayer
from GadgetBox import GadgetBox
from RopChainKernel import RopChainKernel

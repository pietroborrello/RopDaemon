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

def make_symbolic_state(project, stack_length=80):
    """
    converts an input state into a state with symbolic registers
    :return: the symbolic state
    """
    input_state = make_initial_state(project, stack_length)
    symbolic_state = input_state.copy()
    # overwrite all registers
    for reg in reg_list:
        symbolic_state.registers.store(reg, symbolic_state.se.BVS("sreg_" + reg + "-", project.arch.bits))
    # restore sp
    symbolic_state.regs.sp = input_state.regs.sp
    # restore bp
    symbolic_state.regs.bp = input_state.regs.bp
    return symbolic_state


class GadgetsVerifier(object):
    def __init__(self, filename, typed_gadgets):
        self._filename =  filename
        self.typed_gadgets = typed_gadgets

    def verify(self):
        print 'Verifying...'
        gadgets = {}
        for t in self.typed_gadgets:
            for g in self.typed_gadgets[t]:
                #print g
                if g.address not in gadgets:
                    gadgets[g.address] = []
                gadgets[g.address].append(g)
        print 'Found %d different typed gadgets' % len(gadgets)

'''
CopyReg_Gadget(EAX, EBX)(89d8c3, 0x8048735, 0x8048737, ['EAX'], 4)
0x8048735:      mov     eax, ebx
0x8048737:      ret

project = angr.Project('a.out')

initial_state = project.factory.blank_state(
        add_options={angr.options.AVOID_MULTIVALUED_READS, angr.options.AVOID_MULTIVALUED_WRITES,
                     angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH,
                     angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION, angr.options.TRACK_ACTION_HISTORY},
        remove_options=angr.options.resilience | angr.options.simplification)
initial_state.options.discard(angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
initial_state.options.update({angr.options.TRACK_REGISTER_ACTIONS, angr.options.TRACK_MEMORY_ACTIONS,
                                angr.options.TRACK_JMP_ACTIONS, angr.options.TRACK_CONSTRAINT_ACTIONS})


init_state = project.factory.blank_state(addr=0x8048735)

for reg in project.arch.default_symbolic_registers except eip, esp:
init_state.registers.store('eax', init_state.se.BVS("sreg_" + 'eax' + "-", project.arch.bits))
init_state.registers.store('ebx', init_state.se.BVS("sreg_" + 'ebx' + "-", project.arch.bits))


#since ends with ret it will have unconstrained successors
final_state = project.factory.successors(init_state).unconstrained_successors[0]
#final_state.regs.eax is init_state.regs.ebx

final_state.solver.add(final_state.regs.eax != init_state.regs.ebx)
final_state.satisfiable() #must be false

final_state = project.factory.successors(init_state).unconstrained_successors[0]
final_state.solver.add(final_state.regs.eax != init_state.regs.ebx)
final_state.satisfiable() #must be false
    

#project.arch.registers['rsp']
#project.arch.default_symbolic_registers
'''
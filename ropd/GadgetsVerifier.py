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
import sys
import claripy
from GadgetsCollector import FLAGS_MASK

ANGR_MEM = 'mem'
ANGR_READ = 'read'
ANGR_WRITE = 'write'

# TODO: use fully symbolic addresses to manage memory accesses

class ConcretizationChecker(angr.concretization_strategies.SimConcretizationStrategy):

    def __init__(self, type, limit, **kwargs):
        super(ConcretizationChecker, self).__init__(**kwargs)
        self.type = type
        self.limit = limit

    def _concretize(self, memory, addr):
        print 'ADDR: %s' % addr


def make_initial_state(project, stack_length):
    """
    :return: an initial state with a symbolic stack and good options for rop
    """
    initial_state = project.factory.blank_state(
        add_options={angr.options.AVOID_MULTIVALUED_READS, angr.options.AVOID_MULTIVALUED_WRITES,
                     angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH,
                     angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION, angr.options.TRACK_ACTION_HISTORY},
        remove_options=angr.options.resilience | angr.options.simplification)
    initial_state.options.discard(angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
    initial_state.options.update({angr.options.TRACK_REGISTER_ACTIONS, angr.options.TRACK_MEMORY_ACTIONS,
                                  angr.options.TRACK_JMP_ACTIONS, angr.options.TRACK_CONSTRAINT_ACTIONS})
    #initial_state.memory.read_strategies.insert(0, ConcretizationChecker('load', 1))
    #initial_state.memory.write_strategies.insert(0, ConcretizationChecker('store', 1))
    symbolic_stack = initial_state.se.BVS("symbolic_stack", project.arch.bits*stack_length)
    initial_state.memory.store(initial_state.regs.sp, symbolic_stack)
    if initial_state.arch.bp_offset != initial_state.arch.sp_offset:
        initial_state.regs.bp = initial_state.regs.sp + 20*initial_state.arch.bytes
    initial_state.se._solver.timeout = 500  # only solve for half a second at most
    return initial_state

def make_symbolic_state(project, stack_length=8):
    """
    converts an input state into a state with symbolic registers
    :return: the symbolic state
    """
    input_state = make_initial_state(project, stack_length)
    symbolic_state = input_state.copy()
    # overwrite all registers
    for reg in Registers:
        symbolic_state.registers.store(reg.name, symbolic_state.se.BVS("sreg_" + reg.name, project.arch.bits))
    #overwrite flags
    symbolic_state.registers.store('flags', symbolic_state.se.BVS("sreg_" + "flags", project.arch.bits))
    # restore sp
    symbolic_state.regs.sp = input_state.regs.sp
    # restore bp
    symbolic_state.regs.bp = input_state.regs.bp
    return symbolic_state

def verifyStackFix(g, init_state, final_state):
    # check that is unsat to have a different stack fix
    return not final_state.satisfiable(extra_constraints=[final_state.regs.sp - init_state.regs.sp != g.stack_fix])

def verifyModReg(g, init_state, final_state):
    # check preserved regs:
    preserved_regs = []
    for reg in Registers:
        if reg is not Registers.esp and reg not in g.modified_regs:
            preserved_regs.append(reg)
       
    constraints = False
    for reg in preserved_regs:
        constraints = claripy.Or(constraints, final_state.registers.load(reg.name) != init_state.registers.load(reg.name))
    # check that is unsat to have any preserved reg changed
    return not final_state.satisfiable(extra_constraints=[constraints])

    '''# maybe less efficient but more readable
    for reg in preserved_regs:
        if final_state.satisfiable(extra_constraints=[final_state.registers.load(reg.name) != init_state.registers.load(reg.name)]):
            return False
    
    return True'''

def verifyCopyRegGadget(project, g, init_state, final_state):
    return not final_state.satisfiable(extra_constraints=[final_state.registers.load(g.dest.name) != init_state.registers.load(g.src.name)])

def compute_operation(a, op, b):
    if op == Operations.ADD:
        return (a + b) 
    elif op == Operations.SUB:
        return (a - b) 
    elif op == Operations.MUL:
        return (a * b) 
    elif op == Operations.DIV:
        return (a // b) 
    elif op == Operations.XOR:
        return (a ^ b) 
    elif op == Operations.OR:
        return (a | b) 
    elif op == Operations.AND:
        return (a & b) 

def verifyBinOpGadget(project, g, init_state, final_state):
    return not final_state.satisfiable(extra_constraints=
        [final_state.registers.load(g.dest.name) != compute_operation(init_state.registers.load(g.src1.name), g.op, init_state.registers.load(g.src2.name))])

def verifyLoadConstGadget(project, g, init_state, final_state):
    load_content = init_state.memory.load(init_state.regs.sp + g.offset, project.arch.bits / 8, endness=init_state.arch.memory_endness)
    return not final_state.satisfiable(extra_constraints=[final_state.registers.load(g.register.name) != load_content]) 

def verifyLahfGadget(project, g, init_state, final_state):
    flags = (init_state.regs.flags & FLAGS_MASK) | 2
    ah = ((final_state.registers.load(Registers.eax.name) >> 8) & FLAGS_MASK) | 2
    return not final_state.satisfiable(extra_constraints=[ ah != flags])

def verifyReadMemGadget(project, g, init_state, final_state):
    # if fully symboloc memory
    '''mem_content = init_state.memory.load(init_state.registers.load(g.addr_reg.name) + g.offset, project.arch.bits / 8, endness=init_state.arch.memory_endness)
    return not final_state.satisfiable(extra_constraints=[final_state.registers.load(g.dest.name) != mem_content])'''
    for a in final_state.history.filter_actions(read_from=ANGR_MEM):
        # check if it is the read action responsible of the read
        constraints = False
        constraints = claripy.Or(constraints, init_state.registers.load(g.addr_reg.name) + g.offset != a.addr.ast)
        constraints = claripy.Or(constraints, final_state.registers.load(g.dest.name) != a.data.ast)
        # UNSAT that wrong address or wrong dest
        if not final_state.satisfiable(extra_constraints=[constraints]):
            return True
    return False

def verifyWriteMemGadget(project, g, init_state, final_state):
    for a in final_state.history.filter_actions(write_to=ANGR_MEM):
        # check if it is the action responsible for the write
        constraints = False
        constraints = claripy.Or(constraints, init_state.registers.load(g.addr_reg.name) + g.offset != a.addr.ast)
        constraints = claripy.Or(constraints, init_state.registers.load(g.src.name) != a.data.ast)
        if not final_state.satisfiable(extra_constraints=[constraints]):
            return True
    return False

def verifyReadMemOpGadget(project, g, init_state, final_state):
    for a in final_state.history.filter_actions(read_from=ANGR_MEM):
        constraints = False
        constraints = claripy.Or(constraints, init_state.registers.load(g.addr_reg.name) + g.offset != a.addr.ast)
        constraints = claripy.Or(constraints, final_state.registers.load(g.dest.name) != compute_operation(init_state.registers.load(g.dest.name), g.op, a.data.ast))
        if not final_state.satisfiable(extra_constraints=[constraints]):
            return True
    return False

def verifyWriteMemOpGadget(project, g, init_state, final_state):
    # find original data in the memory location
    found = False
    for a in final_state.history.filter_actions(read_from=ANGR_MEM):
        constraints = (init_state.registers.load(g.addr_reg.name) + g.offset != a.addr.ast)
        if not final_state.satisfiable(extra_constraints=[constraints]):
            data = a.data.ast
            found = True
    if not found:
        return False
    for a in final_state.history.filter_actions(write_to=ANGR_MEM):
        constraints = False
        constraints = claripy.Or(constraints, init_state.registers.load(g.addr_reg.name) + g.offset != a.addr.ast)
        constraints = claripy.Or(constraints, a.data.ast != compute_operation(data, g.op, init_state.registers.load(g.src.name)))
        if not final_state.satisfiable(extra_constraints=[constraints]):
            return True
    return False

def verifyOpEspGadget(project, g, init_state, final_state):
    return not final_state.satisfiable(extra_constraints=
        [final_state.regs.sp != compute_operation(init_state.regs.sp + g.stack_fix, g.operation, init_state.registers.load(g.register.name))])

class GadgetsVerifier(object):
    def __init__(self, filename, typed_gadgets):
        self.filename =  filename
        self.typed_gadgets = typed_gadgets

    def verify(self):
        project = angr.Project(self.filename)
        generic_state = make_symbolic_state(project)
        print 'Verifying...'
        gadgets = {}
        for t in self.typed_gadgets:
            for g in self.typed_gadgets[t]:
                #print g
                if g.address not in gadgets:
                    gadgets[g.address] = []
                gadgets[g.address].append(g)
        print 'Found %d different typed gadgets' % len(gadgets)
        verified_gadgets = {}
        for t in Types:
            verified_gadgets[t] = []
        for addr, gad_list in gadgets.iteritems():
            # verify modified registers and stack fix once for all
            if not gad_list:
                print 'DISCARDED: empty list - %x' % addr
                continue
            first_g = gad_list[0]
            init_state = generic_state.copy()
            init_state.regs.ip = first_g.address
            # since ends with ret it will have unconstrained successors
            succ = project.factory.successors(init_state).unconstrained_successors
            if len(succ) == 0:
                print 'DISCARDED: not a valid gadget'
                break
            final_state = succ[0]
            if not verifyModReg(first_g, init_state, final_state):
                print 'DISCARDED: wrong modified regs'
                print first_g.dump()
                continue
        
            for g in gad_list:
                # maybe OpEsp_gadget
                if type(g) is OpEsp_Gadget and verifyOpEspGadget(project, g, init_state, final_state):
                    # add esp to modified regs
                    #g.modified_regs.append(Registers.esp)
                    verified_gadgets[Types.OpEsp].append(g)
                elif not verifyStackFix(g, init_state, final_state):
                    print 'DISCARDED: wrong stack fix'
                    print g
                    print g.dump()
                if type(g) is CopyReg_Gadget and verifyCopyRegGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.CopyReg].append(g)
                elif type(g) is LoadConst_Gadget and verifyLoadConstGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.LoadConst].append(g)
                elif type(g) is BinOp_Gadget and verifyBinOpGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.BinOp].append(g)
                elif type(g) is ReadMem_Gadget and verifyReadMemGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.ReadMem].append(g)
                elif type(g) is WriteMem_Gadget and verifyWriteMemGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.WriteMem].append(g)
                elif type(g) is ReadMemOp_Gadget and verifyReadMemOpGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.ReadMemOp].append(g)
                elif type(g) is WriteMemOp_Gadget and verifyWriteMemOpGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.WriteMemOp].append(g)
                elif type(g) is Lahf_Gadget and verifyLahfGadget(project, g, init_state, final_state):
                    verified_gadgets[Types.Lahf].append(g)
                elif type(g) is OpEsp_Gadget:
                    # just checked
                    continue
                else:
                    print 'DISCARDED:'
                    print g
                    print g.dump()


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
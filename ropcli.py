#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"


import argparse
import ropd
import pickle

COLLECTED_EXTENSION = '.collected'



def collect(binary, do_print=False):
    gadget_collector = ropd.GadgetsCollector(binary)
    typed_gadgets = gadget_collector.analyze()
    if do_print:
        for t in typed_gadgets:
            for g in typed_gadgets[t]:
                print g
    with open(binary + COLLECTED_EXTENSION, 'wb') as collected_file:
        pickle.dump(typed_gadgets, collected_file)
    return typed_gadgets

def verify(binary, typed_gadgets, do_print=True):
    gadgets = {}
    for t in typed_gadgets:
        for g in typed_gadgets[t]:
            #print g
            if g.address not in gadgets:
                gadgets[g.address] = []
            gadgets[g.address].append(g)

    print 'Found %d different typed gadgets' % len(gadgets)


def main():
    parser = argparse.ArgumentParser(
        description="This is RopCLI")
    
    parser.add_argument( '-a', '--architecture', help="Specify architecture (x86 or x86-64)", default="x86")
    
    parser.add_argument('binary', help="Input binary", default=None)

    parser.add_argument('-c', "--collect", help="collect and categorize gadgets", action="store_true")

    parser.add_argument('-v', "--verify", help="formally verify collected gadgets", action="store_true")

    args = parser.parse_args()
    if args.collect:
        typed_gadgets = collect(args.binary)
    else:
        try:
            with open(args.binary + COLLECTED_EXTENSION, 'rb') as collected_file:
                typed_gadgets = pickle.load(collected_file)
        except IOError as e:
            print 'ERROR: %s' % e
            print 'Did you collected gadget before verification?'
            return

    if args.verify:
        verified_gadgets = verify(args.binary, typed_gadgets)
    
    

if __name__ == "__main__":
    main()
    


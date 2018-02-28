#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"


import argparse
import ropd


def main():
    parser = argparse.ArgumentParser(
        description="This is RopCLI")
    
    parser.add_argument(
        '-a',                
        '--architecture',
        help="Specify architecture (x86 or x86-64)",
        default="x86")
    
    parser.add_argument(
        'binary',
        help="Input binary",
        default=None)

    args = parser.parse_args()
    gadget_collector = ropd.GadgetsCollector(args.binary)
    typed_gadgets = gadget_collector.analyze()
    for t in typed_gadgets:
        for g in typed_gadgets[t]:
            print g
    
    

if __name__ == "__main__":
    main()
    


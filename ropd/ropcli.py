#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"


import logging
import json
from enum import Enum

import argparse
import pickle

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
from Gadget import Gadget

COLLECTED_EXTENSION = '.collected'
VERIFIED_EXTENSION = '.verified'
TEST_EXTENSION = '.test'
JSON_EXTENSION = '.json'


def collect(binary, do_print=False):
    gadgets_collector = GadgetsCollector(binary)
    typed_gadgets = gadgets_collector.analyze()
    if do_print:
        for g in typed_gadgets:
            print g
    with open(binary + COLLECTED_EXTENSION, 'wb') as collected_file:
        pickle.dump(typed_gadgets, collected_file)
    print 'Collected gadgets saved in', binary + COLLECTED_EXTENSION
    return typed_gadgets

def verify(binary, do_print=False):
    try:
        with open(binary + COLLECTED_EXTENSION, 'rb') as collected_file:
            typed_gadgets = pickle.load(collected_file)
    except IOError as e:
        print 'ERROR: %s' % e
        print 'Did you collected gadget before verification?'
        return
    gadgets_verifier = GadgetsVerifier(binary, typed_gadgets)
    verified_gadgets = gadgets_verifier.verify()
    if do_print:
        for g in verified_gadgets:
            print g
    with open(binary + VERIFIED_EXTENSION, 'wb') as collected_file:
        pickle.dump(verified_gadgets, collected_file)
    print 'Verified gadgets saved in', binary + VERIFIED_EXTENSION
    return verified_gadgets

def dump_file(binary):
    try:
        with open(binary + VERIFIED_EXTENSION, 'rb') as collected_file:
            typed_gadgets = pickle.load(collected_file)
            for g in typed_gadgets:
                print g
                print g.dump()
    except IOError as e:
        print 'ERROR: %s' % e
        print 'Did you collected and verified gadgets before?'
        return


def to_json(obj):
    if isinstance(obj, Gadget):
        d = { 'type':obj.__class__.__name__[:obj.__class__.__name__.find('_Gadget')], 
              'disasm':obj.disasm(), 'params':obj.param_str()}
        d.update(obj.__dict__)
        # convert bytearray to str
        d['hex'] = str(d['hex']).encode('hex')
        return d
    if isinstance(obj, frozenset):
        return list(obj)
    elif isinstance(obj, Enum):
        return obj.name
    return o.__dict__


def dump_json(binary):
    try:
        with open(binary + VERIFIED_EXTENSION, 'rb') as collected_file:
            with open(binary + JSON_EXTENSION, 'wb') as json_file:
                typed_gadgets = pickle.load(collected_file)
                json_file.write('[')
                for g in typed_gadgets[:-1]:
                    json_file.write(json.dumps(g, default=to_json, ensure_ascii=False))
                    json_file.write(',')
                g = typed_gadgets[-1]
                json_file.write(json.dumps(g, default=to_json, ensure_ascii=False))
                json_file.write(']')
    except IOError as e:
        print 'ERROR: %s' % e
        print 'Did you collected and verified gadgets before?'
        return
    print 'Json gadgets saved in', binary + JSON_EXTENSION

def stats(binary):
    try:
        with open(binary + VERIFIED_EXTENSION, 'rb') as collected_file:
            gadgets = pickle.load(collected_file)
            gadgets_player = GadgetsPlayer(binary, gadgets)
            gadgets_player.stats()
    except IOError as e:
        print 'ERROR: %s' % e
        print 'Did you collected and verified gadgets before?'
        return

def play(binary):
    try:
        with open(binary + VERIFIED_EXTENSION, 'rb') as collected_file:
            gadgets = pickle.load(collected_file)
            gadgets_player = GadgetsPlayer(binary, gadgets)
            gadgets_player.play()
    except IOError as e:
        print 'ERROR: %s' % e
        print 'Did you collected and verified gadgets before?'
        return
            
    
def diff(binary):
    try:
        with open(binary + VERIFIED_EXTENSION, 'rb') as file1:
            l1 = pickle.load(file1)
            logging.info("Diffing")
            typed_gadgets2 = collect(binary)
            l2 = verify(binary)
            for l in l1:
                if l not in l2:
                    print '[+]', l
                    print l.dump()
            for l in l2:
                if l not in l1:
                    print '[-]', l
                    print l.dump()
    except IOError as e:
        print 'ERROR: %s' % e
        print 'You need to have something to compute the delta from! Try to collect and verify gadgets first'
        return
                        


            

def main():
    parser = argparse.ArgumentParser(
        description="This is RopCLI")
    
    parser.add_argument( '-a', '--architecture', help="Specify architecture (x86 or x86-64)", default="x86")
    
    parser.add_argument('binary', help="Input binary", default=None)

    parser.add_argument('-c', "--collect", help="collect and categorize gadgets", action="store_true")

    parser.add_argument('-v', "--verify", help="formally verify collected gadgets", action="store_true")

    parser.add_argument('-p', "--play", help="perform some analysis on verified gadgets", action="store_true")

    parser.add_argument( '-d', '--dump', help="dump gadgets file to a readable format", action="store_true")

    parser.add_argument( '-j', '--json', help="dump gadgets file to json format", action="store_true")

    parser.add_argument('--stats', help="statistics about verified gadgets", action="store_true")

    parser.add_argument('--diff', help="compute another gadget verification and diff with the actual version [AND OVVERRIDE CURRENT VERSION]", action="store_true")

    args = parser.parse_args()
    logging.info('Starting analysis of %s', args.binary)

    if args.collect:
        typed_gadgets = collect(args.binary)

    if args.verify:
        verified_gadgets = verify(args.binary)

    if args.dump:
        dump_file(args.binary)
    if args.json:
        dump_json(args.binary)

    if args.stats:
        stats(args.binary)

    if args.diff:
        diff(args.binary)

    if args.play:
        play(args.binary)
    
    

if __name__ == "__main__":
    main()
    


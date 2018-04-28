#! /usr/bin/env python2

import sys
import os
import argparse

from ropper import *


def get_operands(line):
    """
    Only handles pushes and pops for now.
    """
    return (line[3].replace("{","")
                   .replace("}","")
                   .replace("#","")
                   .split(", "))

def parse_numeric_operand(op):
    try:
        return int(op, base=16)
    except ValueError:
        return None

def calc_sp_delta_arm(gad, arch):
    """
    Analyses a gadget, and returns its estimated stack pointer delta.
    """
    sp_delta = 0
    last_op = 2 if arch == 'ARM' else 1
    for line in gad.lines:
        if line[2] == 'pop':
            regs = get_operands(line)
            sp_delta += len(regs)
        if line[2] == 'push':
            regs = get_operands(line)
            sp_delta -= len(regs)
        if line[2] == 'add' and 'sp' in get_operands(line)[0]:
            ops = get_operands(line)
            n = parse_numeric_operand(ops[last_op])
            if n is not None:
                sp_delta += n
        if line[2] == 'sub' and 'sp' in get_operands(line)[0]:
            ops = get_operands(line)
            n = parse_numeric_operand(ops[last_op])
            if n is not None:
                sp_delta -= n
    return sp_delta
                  

def calc_sp_delta_x86(gad, arch):

    pass
    return 0

def calc_sp_delta(gad, arch):
    if 'ARM' in arch:
        return calc_sp_delta_arm(gad, arch)
    elif 'x86' in arch:
        return calc_sp_delta_x86(gad, arch)

def tabrow(*args):
    return '\t'.join(['{}'.format(x) for x in args])

def get_disasm(gad):
    return '"' + '; '.join([x[1] for x in gad.lines]) + '"'

def main(path, arch, with_disasm=False):
    options = {'color': False,
               'badbytes': '',
               'all': False,
               'inst_count': 16,
               'type': 'rop',
               'detailed': True}

    rs = RopperService(options)
    rs.addFile(path)
    rs.setArchitectureFor(name=path, arch=arch)
    rs.loadGadgetsFor()

    gadgets = rs.getFileFor(name=path).gadgets
    for gadget in gadgets:
        entry = gadget.lines[0][0]
        ret_addr = gadget.lines[-1][0]
        sp_delta = calc_sp_delta(gadget, arch)
        if with_disasm:
            print tabrow(arch, entry, ret_addr, sp_delta, get_disasm(gadget))
        else:
            print tabrow(arch, entry, ret_addr, sp_delta)




def cli():
    """ Command line interface """
    parser = argparse.ArgumentParser(description="generate gadget tables")
    parser.add_argument("--file", metavar="<path>", type=str,
            help="file to harvest gadgets from")
    parser.add_argument("--arch", metavar="<ARM|X86>", type=str, help="architecture")
    parser.add_argument("--disas", action="store_true", type=bool, default=False, 
            help="disassemble")
    args = parser.parse_args()
    if arch == "ARM":
        main(args.file, "ARM", args.disas)
        main(args.file, "ARMTHUMB", args.disas)
    elif arch == "x86":
        main(args.file, args.arch, args.disas)



cli()

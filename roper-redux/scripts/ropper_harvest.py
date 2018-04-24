#! /usr/bin/env python2

import sys
import os

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

def calc_sp_delta(gad, arch):
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


show_disasm = bool(os.environ['SHOW_DISASM']) if 'SHOW_DISASM' in os.environ else False

main(sys.argv[1], "ARMTHUMB", show_disasm)
main(sys.argv[1], "ARM", show_disasm)



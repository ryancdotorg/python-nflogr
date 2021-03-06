#!/usr/bin/env python3

import re
import os, sys
import nflogr

if len(sys.argv) != 3:
    print('arguments must be `group` `count`')
    sys.exit(1)

NFULA_ATTR = {}
with open('/usr/include/linux/netfilter/nfnetlink_log.h') as h:
    enum = None
    count = 0
    for line in h.readlines():
        m = re.match(r'^(enum|[}]|\s+)(?:\s+nfulnl_|_*NFULA_)([a-zA-Z0-9_]+)?.*', line)
        if m:
            if m.group(1) == 'enum':
                enum = m.group(2)
            elif m.group(1) == '}':
                enum = None
            elif enum == 'attr_type':
                NFULA_ATTR[m.group(2)] = count
                count += 1

ATTR_NAME = {v-1: k for k, v in NFULA_ATTR.items()}

# open a listener and dump data in pretty-printed format that can be loaded
# back into nflogr using something like:
#
# nflogr._from_iter(ast.literal_eval(open('dump.lit').read()))
with nflogr.open(int(sys.argv[1]), timeout=1, qthresh=4, enobufs=nflogr.ENOBUFS_HANDLE) as nflog:
    print('[')
    for _ in range(int(sys.argv[2])):
        recv = nflog._recv_raw()
        #print(len(r), file=sys.stderr)
        print('  [')
        for tup in recv:
            print('    ('+repr(tup[0])+', (')
            i = 0
            for attr in tup[1]:
                s = '      '+repr(attr)+', # ' + ATTR_NAME[i]
                if attr != None:
                    s += ' (' + str(len(attr)) + ' bytes)'
                print(s)
                i += 1
            print('    )),')
        print('  ],')
    print(']')

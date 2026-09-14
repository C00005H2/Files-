#!/usr/bin/env python3
"""Disassemble RVA ranges of crackme.exe with capstone."""
import sys, pefile
from capstone import *
BIN='6aa4b6d3585e8875bcbebf80/crackme.exe'
pe=pefile.PE(BIN)
BASE=0x14000000
md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=False
data={}
for s in pe.sections:
    data[s.VirtualAddress]=s.get_data()
def disasm_rva(rva,n):
    # find section
    for va,d in data.items():
        if va<=rva<va+len(d) and rva+n<=va+len(d):
            buf=d[rva-va:rva-va+n]; base=BASE+rva; break
    else:
        # fall back to raw file read at rva (for .data etc.)
        buf=pe.get_data(rva,n); base=BASE+rva
    out=[]
    for i in md.disasm(buf,base):
        out.append(f"{i.address-BASE:06x}: {i.mnemonic} {i.op_str}")
    return out
if __name__=='__main__':
    a=int(sys.argv[1],16); n=int(sys.argv[2],16) if len(sys.argv)>2 else 0x100
    print('\n'.join(disasm_rva(a,n)))

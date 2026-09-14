#!/usr/bin/env python3
"""Build a minimal fake DLL (PE) whose export table maps API names -> addresses.
Used by emu3.py so crackme's custom GetProcAddress (0x6BA0) can resolve APIs."""
import struct, sys

def build_pe(exports, image_base=0x77000000):
    """exports: list of (name:str, addr:int). Returns (bytes, {name:addr})."""
    # Layout (single section 'R' holding everything after headers):
    #   0x00: MZ (64 bytes)
    #   0x40: PE sig + COFF(20) + OptionalHeader(240) + data dirs
    #   section header at 0x188
    #   section raw at 0x200 (RVA 0x1000)
    sec_rva = 0x1000
    sec_raw = 0x1000          # align file offset to RVA so direct load is correct
    hdr_end = 0x1000
    # We'll place: [export dir][address table][ordinal table][name ptr table][names] in section.
    n = len(exports)
    ed_size = 40
    addr_tbl = n*4
    ord_tbl = n*2
    nameptr_tbl = n*4
    # compute name blob size
    names_blob = b''
    name_offs = []
    off = 0
    for name,_ in exports:
        name_offs.append(off)
        wb = name.encode('ascii')+b'\x00'
        names_blob += wb
        off += len(wb)
    sub_total = ed_size+addr_tbl+ord_tbl+nameptr_tbl+len(names_blob)
    sec_size = (sub_total+0xFFF)&~0xFFF
    ed_rva = sec_rva
    addr_rva = ed_rva+ed_size
    ord_rva = addr_rva+addr_tbl
    nameptr_rva = ord_rva+ord_tbl
    names_rva = nameptr_rva+nameptr_tbl

    section = bytearray(sec_size)
    # Export Directory (IMAGE_EXPORT_DIRECTORY, 40 bytes)
    struct.pack_into('<I', section, 0, 0)                 # Characteristics
    struct.pack_into('<I', section, 4, 0)                 # TimeDateStamp
    struct.pack_into('<H', section, 8, 0); struct.pack_into('<H', section,10,0)
    struct.pack_into('<I', section, 12, 0)                # Name RVA (unnamed ok)
    struct.pack_into('<I', section, 16, 1)                # OrdinalBase
    struct.pack_into('<I', section, 20, n)                # NumberOfFunctions
    struct.pack_into('<I', section, 24, n)                # NumberOfNames
    struct.pack_into('<I', section, 28, addr_rva)     # AddressOfFunctions (image RVA)
    struct.pack_into('<I', section, 32, nameptr_rva)  # AddressOfNamePointers (image RVA)
    struct.pack_into('<I', section, 36, ord_rva)      # AddressOfNameOrdinals (image RVA)
    # address table
    for i,(nm,addr) in enumerate(exports):
        struct.pack_into('<I', section, ed_size+i*4, addr & 0xFFFFFFFF)
    # ordinal table
    for i in range(n):
        struct.pack_into('<H', section, ed_size+addr_tbl+i*2, i)
    # name pointer table (image RVAs)
    for i,(nm,_) in enumerate(exports):
        struct.pack_into('<I', section, ed_size+addr_tbl+ord_tbl+i*4, names_rva+name_offs[i])
    # names
    section[ed_size+addr_tbl+ord_tbl+nameptr_tbl:] = names_blob[:len(names_blob)]

    # Build headers
    pe = bytearray(hdr_end)
    pe[0:2]=b'MZ'; struct.pack_into('<I',pe,0x3c,0x80)   # e_lfanew=0x80
    off=0x80
    pe[off:off+4]=b'PE\x00\x00'; off+=4
    # COFF
    struct.pack_into('<HHIIIHH',pe,off,0x8664,1,0,0,0,0xE0,0x2); off+=20
    # Optional header (PE32+, 240 bytes)
    oh=off
    struct.pack_into('<H',pe,oh,0x20B)                    # Magic PE32+
    pe[oh+2]=14; pe[oh+3]=0
    struct.pack_into('<I',pe,oh+4,sec_size)               # SizeOfCode
    struct.pack_into('<I',pe,oh+8,0)                      # SizeOfInitializedData
    struct.pack_into('<I',pe,oh+12,0)                     # SizeOfUninitializedData
    struct.pack_into('<I',pe,oh+16,0x1000)                # AddressOfEntryPoint
    struct.pack_into('<I',pe,oh+20,sec_rva)               # BaseOfCode
    struct.pack_into('<Q',pe,oh+24,image_base)            # ImageBase
    struct.pack_into('<I',pe,oh+32,0x1000)                # SectionAlignment
    struct.pack_into('<I',pe,oh+36,0x200)                 # FileAlignment
    struct.pack_into('<H',pe,oh+40,6);struct.pack_into('<H',pe,oh+42,0)   # OS ver
    struct.pack_into('<H',pe,oh+44,0);struct.pack_into('<H',pe,oh+46,0)   # img ver
    struct.pack_into('<H',pe,oh+48,6);struct.pack_into('<H',pe,oh+50,0)   # subsys ver
    struct.pack_into('<I',pe,oh+64,0x1000)                # Win32VersionValue? (pad) 
    struct.pack_into('<I',pe,oh+56,sec_size+0x1000)       # SizeOfImage
    struct.pack_into('<I',pe,oh+60,hdr_end)               # SizeOfHeaders
    struct.pack_into('<I',pe,oh+64,0)                     # CheckSum
    struct.pack_into('<H',pe,oh+68,3)                      # Subsystem console
    struct.pack_into('<H',pe,oh+70,0x40)                   # DllCharacteristics
    struct.pack_into('<Q',pe,oh+72,0x100000);struct.pack_into('<Q',pe,oh+80,0x1000)
    struct.pack_into('<Q',pe,oh+88,0x100000);struct.pack_into('<Q',pe,oh+96,0x1000)
    struct.pack_into('<I',pe,oh+100,16)                    # LoaderFlags
    struct.pack_into('<I',pe,oh+104,16)                    # NumberOfRvaAndSizes
    # Data directories start at oh+0x70 (112); index 0 = Export
    dd=oh+0x70
    struct.pack_into('<II',pe,dd,ed_rva,ed_size)          # Export dir
    # Section header (1 section)
    sh=oh+240
    sec_name=b'.rdata\x00\x00'
    struct.pack_into('<I',pe,sh+8,sec_size)               # VirtualSize
    struct.pack_into('<I',pe,sh+12,sec_rva)
    struct.pack_into('<I',pe,sh+16,sec_size)              # SizeOfRawData
    struct.pack_into('<I',pe,sh+20,sec_raw)
    struct.pack_into('<I',pe,sh+24,0)
    struct.pack_into('<I',pe,sh+28,0);struct.pack_into('<I',pe,sh+32,0)
    struct.pack_into('<I',pe,sh+36,0xC0000040)            # RWX
    pe[sh:sh+8]=sec_name
    assert sh+40 <= hdr_end, (sh+40,hdr_end)
    # pad to hdr_end then append section
    out = bytes(pe)+bytes(section)
    addrmap={nm:(image_base+ (addr&0xFFFFFFFF)) for nm,addr in exports}
    return out, addrmap

if __name__=='__main__':
    import json
    spec=json.loads(sys.argv[1])  # {"base":..,"apis":[{"name":..,"addr":..}]}
    data,amap=build_pe([(a['name'],a['addr']) for a in spec['apis']], image_base=spec.get('base',0x77000000))
    open(spec['out'],'wb').write(data)
    print("wrote",spec['out'],len(data),"bytes;",len(amap),"exports")

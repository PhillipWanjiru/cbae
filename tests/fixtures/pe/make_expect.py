#!/usr/bin/env python3
"""make_expect.py FILE > FILE.expect - what a real PE32+ file says, as plain numbers, for test_pe_real.

The records are read straight from the bytes (struct), then checked against two independent readers: pefile (headers, sections, imports,
exports, base relocations, debug directory) and LLVM's llvm-readobj (the number of imports, exports and relocation entries). Any
disagreement stops the script, so what is written is what three programs agree on. The loader under test is not involved.

Format (one record per line, decimal numbers, the name last because it is the only field that can hold anything):
  pe   <machine> <sections> <file characteristics> <entry rva> <image base> <size of image> <size of headers> <checksum> <subsystem>
       <dll characteristics> <data directories declared> <file size>
  dir  <index> <rva> <size>                                                 (every declared data directory, empty ones too)
  sec  <index> <virtual size> <rva> <raw size> <raw pointer> <characteristics> <name>
  imp  <descriptor> <iat rva> <slot> <N or O> <hint or ordinal> <dll> <name or ->    (every entry of every import lookup table)
  exp  <ordinal base> <functions> <names> <dll>                              (the export directory header, if there is one)
  eat  <slot> <rva> <forwarder string or ->                                  (every slot of the export address table)
  enm  <index> <slot> <name>                                                 (every entry of the name pointer and ordinal tables)
  rel  <page rva> <block size> <index> <type> <offset in page>               (every entry of every base relocation block)
  dbg  <type> <size> <rva> <pointer>                                         (every debug directory entry)
  pdb  <path>                                                                (the first CodeView RSDS record)
"""
import re, struct, subprocess, sys

import pefile


def main(path):
    data = open(path, 'rb').read()
    n = len(data)

    def u16(o): return struct.unpack_from('<H', data, o)[0]
    def u32(o): return struct.unpack_from('<I', data, o)[0]
    def u64(o): return struct.unpack_from('<Q', data, o)[0]

    def cstr(o):
        e = data.index(b'\0', o)
        return data[o:e].decode('latin-1')

    assert data[:2] == b'MZ'
    lfanew = u32(0x3C)
    assert data[lfanew:lfanew + 4] == b'PE\0\0'
    machine, nsec, _stamp, _symptr, _nsyms, optsz, fchars = struct.unpack_from('<HHIIIHH', data, lfanew + 4)
    opt = lfanew + 24
    assert u16(opt) == 0x20B, 'only PE32+'
    entry, ib = u32(opt + 16), u64(opt + 24)
    size_of_image, size_of_headers, checksum = u32(opt + 56), u32(opt + 60), u32(opt + 64)
    subsystem, dllchars, ndirs = u16(opt + 68), u16(opt + 70), u32(opt + 108)
    assert opt + 112 + 8 * ndirs == opt + optsz, 'a fixture has exactly the directories it declares'
    dirs = [(u32(opt + 112 + 8 * i), u32(opt + 116 + 8 * i)) for i in range(ndirs)]

    out = ['pe %d %d %d %d %d %d %d %d %d %d %d %d' % (machine, nsec, fchars, entry, ib, size_of_image, size_of_headers, checksum, subsystem, dllchars, ndirs, n)]
    for i, (r, s) in enumerate(dirs):
        out.append('dir %d %d %d' % (i, r, s))

    secs = []
    for i in range(nsec):
        h = opt + optsz + 40 * i
        name = data[h:h + 8].rstrip(b'\0').decode('latin-1')
        vsize, rva, rawsize, rawptr, ch = u32(h + 8), u32(h + 12), u32(h + 16), u32(h + 20), u32(h + 36)
        secs.append(dict(name=name, vsize=vsize, rva=rva, rawsize=rawsize, rawptr=rawptr, chars=ch))
        out.append('sec %d %d %d %d %d %d %s' % (i, vsize, rva, rawsize, rawptr, ch, name))
        assert rawptr + rawsize <= n and name, 'a real file is complete'

    def off_of(rva):
        """the file offset of an RVA: in the raw data of a section, or in the headers"""
        for s in secs:
            ext = s['vsize'] or s['rawsize']
            if s['rva'] <= rva < s['rva'] + ext:
                assert rva - s['rva'] < s['rawsize'], 'an RVA that is not in the file: %x' % rva
                return s['rawptr'] + rva - s['rva']
        assert rva < size_of_headers
        return rva

    # ---- imports
    imports = []                                      # (dll, [(kind, hint_or_ordinal, name, iat_rva)])
    ilt_total = 0
    if dirs[1][0]:
        o = off_of(dirs[1][0])
        d = 0
        while True:
            ilt, _ts, _fwd, name_rva, iat = struct.unpack_from('<IIIII', data, o + 20 * d)
            if name_rva == 0 and iat == 0 and ilt == 0:
                break
            assert name_rva and iat and ilt, 'a real descriptor is complete'
            dll = cstr(off_of(name_rva))
            entries = []
            t = off_of(ilt)
            slot = 0
            while True:
                ent = u64(t + 8 * slot)
                if ent == 0:
                    break
                if ent >> 63:
                    assert (ent & ~(1 << 63)) < 0x10000, 'an ordinal import has only the ordinal'
                    entries.append(('O', ent & 0xFFFF, '-', iat + 8 * slot))
                else:
                    assert ent < (1 << 31)
                    hn = off_of(ent)
                    entries.append(('N', u16(hn), cstr(hn + 2), iat + 8 * slot))
                slot += 1
            imports.append((dll, entries))
            for k, (kind, v, nm, iat_rva) in enumerate(entries):
                out.append('imp %d %d %d %s %d %s %s' % (d, iat, k, kind, v, dll, nm))
            ilt_total += len(entries)
            d += 1

    # ---- exports
    exports = []                                      # (slot, ordinal, rva, forwarder or None, name or None)
    if dirs[0][0]:
        o = off_of(dirs[0][0])
        _ch, _ts, _maj, _min, name_rva, base, nfuncs, nnames, eat_rva, names_rva, ords_rva = struct.unpack_from('<IIHHIIIIIII', data, o)
        dll = cstr(off_of(name_rva))
        out.append('exp %d %d %d %s' % (base, nfuncs, nnames, dll))
        eat = [u32(off_of(eat_rva) + 4 * k) for k in range(nfuncs)]
        names = {}
        for i in range(nnames):
            slot = u16(off_of(ords_rva) + 2 * i)
            nm = cstr(off_of(u32(off_of(names_rva) + 4 * i)))
            assert slot < nfuncs and slot not in names, 'a real export table is consistent'
            names[slot] = nm
            out.append('enm %d %d %s' % (i, slot, nm))
        for slot, rva in enumerate(eat):
            fwd = None
            if rva and dirs[0][0] <= rva < dirs[0][0] + dirs[0][1]:
                fwd = cstr(off_of(rva))
            out.append('eat %d %d %s' % (slot, rva, fwd or '-'))
            if rva:
                exports.append((slot, base + slot, rva, fwd, names.get(slot)))

    # ---- base relocations
    relocs = []                                       # (page, size, index, type, offset)
    if dirs[5][0]:
        o = off_of(dirs[5][0])
        pos = 0
        while pos < dirs[5][1]:
            page, bsz = u32(o + pos), u32(o + pos + 4)
            assert bsz >= 8 and pos + bsz <= dirs[5][1]
            for k in range((bsz - 8) // 2):
                e = u16(o + pos + 8 + 2 * k)
                relocs.append((page, bsz, k, e >> 12, e & 0xFFF))
                out.append('rel %d %d %d %d %d' % relocs[-1])
            pos += bsz
        assert pos == dirs[5][1]

    # ---- debug directory
    pdb = None
    dbg = []
    if dirs[6][0]:
        o = off_of(dirs[6][0])
        assert dirs[6][1] % 28 == 0
        for k in range(dirs[6][1] // 28):
            _ch, _ts, _maj, _min, typ, size, rva, ptr = struct.unpack_from('<IIHHIIII', data, o + 28 * k)
            dbg.append((typ, size, rva, ptr))
            out.append('dbg %d %d %d %d' % (typ, size, rva, ptr))
            if typ == 2 and pdb is None and data[ptr:ptr + 4] == b'RSDS':
                pdb = cstr(ptr + 24)
        if pdb:
            out.append('pdb ' + pdb)

    # ---- agreement with pefile
    pe = pefile.PE(path)
    assert pe.FILE_HEADER.Machine == machine and pe.FILE_HEADER.NumberOfSections == nsec and pe.FILE_HEADER.Characteristics == fchars
    oh = pe.OPTIONAL_HEADER
    assert (oh.AddressOfEntryPoint, oh.ImageBase, oh.SizeOfImage, oh.SizeOfHeaders, oh.CheckSum, oh.Subsystem, oh.DllCharacteristics, oh.NumberOfRvaAndSizes) == \
           (entry, ib, size_of_image, size_of_headers, checksum, subsystem, dllchars, ndirs)
    for i, (r, s) in enumerate(dirs):
        assert (oh.DATA_DIRECTORY[i].VirtualAddress, oh.DATA_DIRECTORY[i].Size) == (r, s), i
    for s, p in zip(secs, pe.sections):
        assert (p.Name.rstrip(b'\0').decode('latin-1'), p.Misc_VirtualSize, p.VirtualAddress, p.SizeOfRawData, p.PointerToRawData, p.Characteristics) == \
               (s['name'], s['vsize'], s['rva'], s['rawsize'], s['rawptr'], s['chars'])
    assert len(pe.sections) == nsec

    imp_p = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
    assert len(imp_p) == len(imports)
    for e, (dll, entries) in zip(imp_p, imports):
        assert e.dll.decode('latin-1') == dll and len(e.imports) == len(entries), dll
        for im, (kind, v, nm, iat_rva) in zip(e.imports, entries):
            assert im.address == ib + iat_rva, (dll, nm)
            if kind == 'O':
                assert im.import_by_ordinal and im.ordinal == v and im.name is None, (dll, v)
            else:
                assert not im.import_by_ordinal and im.name.decode('latin-1') == nm and im.hint == v, (dll, nm)

    if exports or dirs[0][0]:
        ex = pe.DIRECTORY_ENTRY_EXPORT
        assert ex.struct.Base == base and ex.struct.NumberOfFunctions == nfuncs and ex.struct.NumberOfNames == nnames
        assert len(ex.symbols) == len(exports), (len(ex.symbols), len(exports))
        by_ord = {s.ordinal: s for s in ex.symbols}
        for slot, ordinal, rva, fwd, nm in exports:
            s = by_ord[ordinal]
            assert s.address == rva and (s.name.decode('latin-1') if s.name else None) == nm, (ordinal, nm)
            assert (s.forwarder.decode('latin-1') if s.forwarder else None) == fwd, (ordinal, fwd)

    rel_p = []
    for b in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
        for k, e in enumerate(b.entries):
            rel_p.append((b.struct.VirtualAddress, b.struct.SizeOfBlock, k, e.type, e.rva - b.struct.VirtualAddress))
    assert rel_p == relocs, 'base relocations differ from pefile'

    dbg_p = [(d.struct.Type, d.struct.SizeOfData, d.struct.AddressOfRawData, d.struct.PointerToRawData) for d in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])]
    assert dbg_p == dbg, 'debug entries differ from pefile'
    if pdb:
        got = [d.entry.PdbFileName.rstrip(b'\0').decode('latin-1') for d in pe.DIRECTORY_ENTRY_DEBUG if d.struct.Type == 2 and hasattr(d.entry, 'PdbFileName')]
        assert got and got[0] == pdb, (got, pdb)

    # ---- agreement with llvm-readobj: the counts
    def readobj(flag):
        return subprocess.run(['llvm-readobj-18', flag, path], capture_output=True, text=True, check=True).stdout
    assert len(re.findall(r'^\s*Symbol: ', readobj('--coff-imports'), re.M)) == ilt_total, 'import count differs from llvm-readobj'
    if exports or dirs[0][0]:
        assert len(re.findall(r'^\s*Export \{', readobj('--coff-exports'), re.M)) == len(exports), 'export count differs from llvm-readobj'
    if dirs[5][0]:
        absolute = sum(1 for r in relocs if r[3] == 0)
        got = len(re.findall(r'^\s*Entry \{', readobj('--coff-basereloc'), re.M))
        assert got in (len(relocs), len(relocs) - absolute), 'relocation count differs from llvm-readobj: %d vs %d' % (got, len(relocs))

    sys.stdout.write('# %s: made by make_expect.py (pefile %s; counts agree with llvm-readobj)\n' % (path.split('/')[-1], pefile.__version__))
    sys.stdout.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])

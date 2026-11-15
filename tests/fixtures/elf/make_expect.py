#!/usr/bin/env python3
"""make_expect.py FILE > FILE.expect - what a real ELF file says, as plain numbers, for test_elf_real.

The records are read straight from the bytes (struct), then checked against two independent readers: pyelftools (names, values,
relocation entries) and binutils' readelf (the number of sections, symbols and relocation entries). Any disagreement stops the
script, so what is written is what three programs agree on. The loader under test is not involved.

Format (one record per line, decimal numbers, the name last because it is the only field that can hold anything):
  elf   <e_type> <e_machine> <e_entry> <e_shnum> <index of the first SHT_SYMTAB or 0>
  sec   <index> <sh_type> <sh_flags> <sh_addr> <sh_offset> <sh_size> <sh_addralign> <sh_entsize> <sh_link> <sh_info> <name>
  sym   <index> <binding> <type> <st_shndx> <st_value> <st_size> <name or ->        (of the first SHT_SYMTAB)
  rel   <section index> <entry> <r_offset> <symbol index> <type> <addend>           (every entry of every SHT_RELA section)
  ksym  <string>                                                                    (each string of __ksymtab_strings)
  meta  <key> <value>                                                               (first license, author, description, vermagic of .modinfo)
"""
import re, struct, subprocess, sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
import elftools

BIND = {'STB_LOCAL': 0, 'STB_GLOBAL': 1, 'STB_WEAK': 2, 'STB_GNU_UNIQUE': 10}
TYPE = {'STT_NOTYPE': 0, 'STT_OBJECT': 1, 'STT_FUNC': 2, 'STT_SECTION': 3, 'STT_FILE': 4, 'STT_COMMON': 5, 'STT_TLS': 6, 'STT_GNU_IFUNC': 10}
SHN = {'SHN_UNDEF': 0, 'SHN_ABS': 0xFFF1, 'SHN_COMMON': 0xFFF2, 'SHN_XINDEX': 0xFFFF}


def cstr(tab, off):
    end = tab.index(b'\0', off)
    return tab[off:end].decode('latin-1')


def main(path):
    data = open(path, 'rb').read()
    assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1, 'only 64-bit little-endian ELF'
    e_type, e_machine, _v, e_entry, _phoff, e_shoff, _fl, _eh, _phes, _phn, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    assert e_shentsize == 64 and e_shnum != 0 and e_shnum < 0xFF00 and e_shstrndx < e_shnum, 'a fixture needs no extended numbering'

    secs = []
    for i in range(e_shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', data, e_shoff + 64 * i)
        secs.append(dict(name=name, type=typ, flags=flags, addr=addr, off=off, size=size, link=link, info=info, align=align, entsize=entsize))
    sh = secs[e_shstrndx]
    shstr = data[sh['off']:sh['off'] + sh['size']]
    for s in secs:
        s['name'] = cstr(shstr, s['name'])

    out = []
    symtab = next((i for i, s in enumerate(secs) if s['type'] == 2), 0)
    out.append('elf %d %d %d %d %d' % (e_type, e_machine, e_entry, e_shnum, symtab))
    for i, s in enumerate(secs):
        out.append('sec %d %d %d %d %d %d %d %d %d %d %s' % (i, s['type'], s['flags'], s['addr'], s['off'], s['size'], s['align'], s['entsize'], s['link'], s['info'], s['name'] or '-'))

    # ---- symbols
    syms = []
    if symtab:
        st = secs[symtab]
        strs = secs[st['link']]
        stab = data[strs['off']:strs['off'] + strs['size']]
        assert st['size'] % 24 == 0 and st['entsize'] == 24
        for k in range(st['size'] // 24):
            n, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, st['off'] + 24 * k)
            syms.append((k, info >> 4, info & 15, shndx, value, size, cstr(stab, n)))
        for k, b, t, shndx, v, sz, nm in syms:
            if k:
                out.append('sym %d %d %d %d %d %d %s' % (k, b, t, shndx, v, sz, nm or '-'))

    # ---- relocation entries
    nrel = {}
    for i, s in enumerate(secs):
        if s['type'] == 4:
            assert s['size'] % 24 == 0 and s['entsize'] == 24
            nrel[i] = s['size'] // 24
            for k in range(s['size'] // 24):
                r_off, r_info, r_add = struct.unpack_from('<QQq', data, s['off'] + 24 * k)
                out.append('rel %d %d %d %d %d %d' % (i, k, r_off, r_info >> 32, r_info & 0xFFFFFFFF, r_add))

    # ---- __ksymtab_strings and .modinfo
    for s in secs:
        if s['name'] == '__ksymtab_strings':
            for t in data[s['off']:s['off'] + s['size']].split(b'\0'):
                if t: out.append('ksym ' + t.decode('latin-1'))
            break
    for s in secs:
        if s['name'] == '.modinfo':
            seen = set()
            for t in data[s['off']:s['off'] + s['size']].split(b'\0'):
                if b'=' in t:
                    k, v = t.decode('latin-1').split('=', 1)
                    if k in ('license', 'author', 'description', 'vermagic') and k not in seen:
                        seen.add(k)
                        out.append('meta %s %s' % (k, v))
            break

    # ---- agreement with pyelftools
    with open(path, 'rb') as fh:
        ef = ELFFile(fh)
        assert ef.num_sections() == e_shnum
        for i, s in enumerate(ef.iter_sections()):
            assert s.name == (secs[i]['name']), (i, s.name, secs[i]['name'])
            assert s['sh_size'] == secs[i]['size'] and s['sh_addr'] == secs[i]['addr'] and s['sh_offset'] == secs[i]['off'], i
            assert s['sh_link'] == secs[i]['link'] and s['sh_info'] == secs[i]['info'] and s['sh_flags'] == secs[i]['flags'], i
        if symtab:
            ps = ef.get_section(symtab)
            assert isinstance(ps, SymbolTableSection) and ps.num_symbols() == len(syms)
            for (k, b, t, shndx, v, sz, nm), y in zip(syms, ps.iter_symbols()):
                assert y.name == nm and y['st_value'] == v and y['st_size'] == sz, (k, nm)
                assert BIND.get(y['st_info']['bind'], b) == b and TYPE.get(y['st_info']['type'], t) == t, (k, nm, y['st_info'])
                got = SHN.get(y['st_shndx'], y['st_shndx'])
                assert got == shndx, (k, nm, got, shndx)
        for i, n in nrel.items():
            rs = ef.get_section(i)
            assert isinstance(rs, RelocationSection) and rs.num_relocations() == n
            for k, r in enumerate(rs.iter_relocations()):
                r_off, r_info, r_add = struct.unpack_from('<QQq', data, secs[i]['off'] + 24 * k)
                assert r['r_offset'] == r_off and r['r_info_sym'] == r_info >> 32 and r['r_info_type'] == (r_info & 0xFFFFFFFF) and r['r_addend'] == r_add, (i, k)

    # ---- agreement with readelf: the counts
    def readelf(*a):
        return subprocess.run(['readelf', '-W', *a, path], capture_output=True, text=True, check=True).stdout
    sec_lines = [l for l in readelf('-S').splitlines() if re.match(r'^\s*\[\s*\d+\]', l)]
    assert len(sec_lines) == e_shnum, (len(sec_lines), e_shnum)
    m = re.findall(r"Symbol table '([^']*)' contains (\d+) entries", readelf('-s'))
    if symtab:
        assert ('.symtab', str(len(syms))) in m, m
    rel_counts = re.findall(r"Relocation section '([^']*)' at offset 0x[0-9a-f]+ contains (\d+) entr", readelf('-r'))
    assert sorted((n, int(c)) for n, c in rel_counts) == sorted((secs[i]['name'], c) for i, c in nrel.items()), (rel_counts, nrel)

    sys.stdout.write('# %s: made by make_expect.py (pyelftools %s, %s)\n' % (path.split('/')[-1], elftools.__version__, readelf('-v').splitlines()[0] if False else 'readelf agrees on counts'))
    sys.stdout.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])

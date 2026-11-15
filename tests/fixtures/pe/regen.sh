#!/bin/sh
# regen.sh - rebuilds the PE fixtures and their expectations. The committed drv.sys, drv.min.sys, lib.dll, lib.arm64.dll and .expect
# files are what the test uses; this script is only needed to change a fixture. It needs clang, lld-link and llvm-dlltool (LLVM 18),
# llvm-readobj, and python3 with pefile (pip install pefile). Nothing from a Windows SDK is used.
#   usage: tests/fixtures/pe/regen.sh
set -eu
cd "$(dirname "$0")"
CL="${CLANG:-clang-18}"; LINK="${LLD_LINK:-lld-link-18}"; DLLTOOL="${LLVM_DLLTOOL:-llvm-dlltool-18}"
X64="--target=x86_64-pc-windows-msvc"; A64="--target=aarch64-pc-windows-msvc"
for d in ntoskrnl hal kernel32; do $DLLTOOL -m i386:x86-64 -d $d.def -l $d.lib; done
$DLLTOOL -m arm64 -d kernel32.def -l kernel32.arm64.lib
COMMON="-O2 -ffreestanding -fno-stack-protector -fno-builtin -fno-ident -funwind-tables"
$CL $X64 $COMMON -mno-red-zone -c drv.c -o drv.obj
$CL $X64 $COMMON -mno-red-zone -c lib.c -o lib.obj
$CL $A64 $COMMON -c lib.c -o lib.arm64.obj
# a driver: INIT section (discardable), imports from ntoskrnl.exe and HAL.dll (one by ordinal), unwind data, a CodeView path, .reloc
$LINK /subsystem:native /driver /entry:DriverEntry /nodefaultlib /base:0x140000000 /dynamicbase /highentropyva:no /section:INIT,ERD \
      /debug /pdb:drv.pdb /pdbaltpath:'C:\fixture\drv.pdb' /brepro /out:drv.sys drv.obj ntoskrnl.lib hal.lib
# the same driver with nothing optional: fixed address (no .reloc), no debug directory, section alignment = file alignment = 512 (a flat image: RVA = file offset)
$LINK /subsystem:native /driver /entry:DriverEntry /nodefaultlib /base:0x140000000 /fixed /dynamicbase:no /debug:none /align:512 /filealign:512 /section:INIT,ERD \
      /brepro /out:drv.min.sys drv.obj ntoskrnl.lib hal.lib
# a DLL: exports by name, by ordinal only (7), a forwarder and a data export; imports from kernel32
$LINK /dll /noentry /nodefaultlib /base:0x180000000 /dynamicbase /highentropyva:no /brepro \
      /export:add /export:uptime /export:hidden_by_ordinal,@7,NONAME /export:exported_data,DATA /export:forwarded=KERNEL32.GetTickCount \
      /out:lib.dll lib.obj kernel32.lib
# the same DLL for ARM64
$LINK /dll /noentry /nodefaultlib /machine:arm64 /base:0x180000000 /dynamicbase /brepro \
      /export:add /export:uptime /export:hidden_by_ordinal,@7,NONAME /export:exported_data,DATA /export:forwarded=KERNEL32.GetTickCount \
      /out:lib.arm64.dll lib.arm64.obj kernel32.arm64.lib
rm -f drv.pdb drv.lib drv.min.lib lib.lib lib.exp lib.arm64.lib lib.arm64.exp *.obj ntoskrnl.lib hal.lib kernel32.lib kernel32.arm64.lib
for f in drv.sys drv.min.sys lib.dll lib.arm64.dll; do python3 make_expect.py "$f" > "$f.expect"; done
{ echo "clang: $($CL --version | head -1)"; echo "lld-link: $($LINK --version | head -1)"; } > TOOLCHAIN
ls -l drv.sys drv.min.sys lib.dll lib.arm64.dll *.expect

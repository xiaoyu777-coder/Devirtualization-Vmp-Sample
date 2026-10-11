import sys, pefile
from capstone import *

PE = "VMPTestAndResearch.vmp.exe"
pe = pefile.PE(PE, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)

def read(va, n):
    rva = va - IB
    for s in pe.sections:
        vsz = max(s.Misc_VirtualSize, len(s.get_data()))
        if s.VirtualAddress <= rva < s.VirtualAddress + vsz:
            return pe.get_data(rva, min(n, s.VirtualAddress + vsz - rva))
    return None

for arg in sys.argv[1:]:
    if ":" in arg:
        va, cnt = arg.split(":")
        va = int(va, 16); cnt = int(cnt)
    else:
        va = int(arg, 16); cnt = 40
    data = read(va, 16 * cnt)
    print("=== %x (%d) ===" % (va, cnt))
    if not data:
        print("  <unmapped>")
        continue
    n = 0
    for insn in md.disasm(data, va):
        print("  %x  %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
        n += 1
        if n >= cnt:
            break

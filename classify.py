import sys, pefile, collections
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
    return b""

h = [int(x, 16) for x in open(r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\handlers.txt")]
uniq = list(dict.fromkeys(h))
print("total dispatches:", len(h), " unique handlers:", len(uniq))
n_insn = int(sys.argv[1]) if len(sys.argv) > 1 else 8
for a in uniq:
    data = read(a, 16 * n_insn)
    insns = list(md.disasm(data, a))[:n_insn]
    print("\n== %x (used %d) ==" % (a, h.count(a)))
    for ins in insns:
        print("   %-8s %s" % (ins.mnemonic, ins.op_str))

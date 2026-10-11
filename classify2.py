import pefile
from capstone import *

PE = r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\VMPTestAndResearch.vmp.exe"
pe = pefile.PE(PE, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)

def read(va, n):
    try:
        return pe.get_data(va - IB, n)
    except Exception:
        return b""

h = [int(x, 16) for x in open(r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\handlers.txt")]
uniq = list(dict.fromkeys(h))
for a in uniq:
    insns = list(md.disasm(read(a, 16 * 200), a))[:200]
    sel = [i for i in insns if ("r11" in i.op_str or "[r10" in i.op_str)]
    print("== %x (n=%d) ==" % (a, h.count(a)))
    for i in sel[:9]:
        print("   %-8s %s" % (i.mnemonic, i.op_str))

import struct, pefile
from unicorn import *
from unicorn.x86_const import *

PE = r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\VMPTestAndResearch.devirt.exe"
pe = pefile.PE(PE)
IB = pe.OPTIONAL_HEADER.ImageBase
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(IB, (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF)
mu.mem_write(IB, pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders])
for s in pe.sections:
    d = s.get_data()
    if d:
        mu.mem_write(IB + s.VirtualAddress, d)

STACK_TOP = 0x70000000
mu.mem_map(STACK_TOP - 0x100000, 0x100000)
mu.reg_write(UC_X86_REG_RSP, (STACK_TOP - 0x1000) & ~0xF)

FAKE = 0x51000000
mu.mem_map(FAKE, 0x3000)
mu.mem_write(FAKE, struct.pack("<Q", FAKE + 0x1000))

STUB = 0x50000000
mu.mem_map(STUB, 0x1000)
stub_api = {}
i = 0
for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    dll = ent.dll.decode(errors="replace")
    for imp in ent.imports:
        nm = imp.name.decode(errors="replace") if imp.name else str(imp.ordinal)
        if "?cout@" in nm:
            mu.mem_write(imp.address, struct.pack("<Q", FAKE)); continue
        addr = STUB + i*8
        stub_api[addr] = dll + "!" + nm
        mu.mem_write(imp.address, struct.pack("<Q", addr))
        i += 1

calls = []
def on_stub(uc, a, sz, ud):
    calls.append(stub_api.get(a, "?"))
    ret = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
    uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_RIP, ret)
mu.hook_add(UC_HOOK_CODE, on_stub, begin=STUB, end=STUB + 0x1000)

try:
    mu.emu_start(0x140012380, 0, count=200000)
    print("devirt main ran OK")
except UcError as e:
    print("UC ERROR:", e, "rip=", hex(mu.reg_read(UC_X86_REG_RIP)))
print("api calls:", calls)
print("rax (ret val):", mu.reg_read(UC_X86_REG_RAX))

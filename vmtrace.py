import sys, struct, traceback, collections
import pefile
from unicorn import *
from unicorn.x86_const import *

PE   = r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\VMPTestAndResearch.vmp.exe"
START = 0x1401FC653          # vm_entry reached from main
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 300000
TRACE_FILE = r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\trace.txt"

pe = pefile.PE(PE)
IB = pe.OPTIONAL_HEADER.ImageBase
SIZE = pe.OPTIONAL_HEADER.SizeOfImage

mu = Uc(UC_ARCH_X86, UC_MODE_64)
IMG = (SIZE + 0xFFF) & ~0xFFF
mu.mem_map(IB, IMG)
mu.mem_write(IB, pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders])
for s in pe.sections:
    d = s.get_data()
    if d:
        mu.mem_write(IB + s.VirtualAddress, d)

# big stack
STACK_TOP = 0x70000000
STACK_SZ  = 0x02000000
mu.mem_map(STACK_TOP - STACK_SZ, STACK_SZ)
rsp = (STACK_TOP - 0x1000) & ~0xF
mu.reg_write(UC_X86_REG_RSP, rsp)

# minimal TEB/PEB so anti-debug / gs: reads don't fault
TEB = 0x7FF00000
mu.mem_map(TEB, 0x2000)
PEB = TEB + 0x1000
mu.mem_write(TEB + 0x60, struct.pack("<Q", PEB))   # TEB->ProcessEnvironmentBlock
mu.mem_write(PEB + 0x02, b"\x00")                  # PEB->BeingDebugged = 0
mu.mem_write(TEB + 0x30, struct.pack("<Q", TEB))   # TEB->Self
mu.reg_write(UC_X86_REG_GS_BASE, TEB)

# ---- import stubs -------------------------------------------------------
STUB_BASE = 0x50000000
mu.mem_map(STUB_BASE, 0x1000)
FAKE = 0x51000000
mu.mem_map(FAKE, 0x3000)               # fake std::cout object (zeroed)
mu.mem_write(FAKE, struct.pack("<Q", FAKE + 0x1000))   # object->field0 -> valid ptr
stub_api = {}
idx = 0
for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    dll = ent.dll.decode(errors="replace")
    for imp in ent.imports:
        nm = imp.name.decode(errors="replace") if imp.name else str(imp.ordinal)
        if "?cout@" in nm:
            mu.mem_write(imp.address, struct.pack("<Q", FAKE))
            continue
        addr = STUB_BASE + idx * 8
        stub_api[addr] = f"{dll}!{nm}"
        mu.mem_write(imp.address, struct.pack("<Q", addr))
        idx += 1
print("import stubs:", idx)

api_calls = []
def on_stub(uc, a, sz, ud):
    name = stub_api.get(a, "??")
    # return to caller of the stub
    ret = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
    api_calls.append(name)
    uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_RIP, ret)
mu.hook_add(UC_HOOK_CODE, on_stub, begin=STUB_BASE, end=STUB_BASE + 0x1000)

for r in (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
          UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
          UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
          UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15):
    mu.reg_write(r, 0)

trace = []
rets = []          # (origin_ret_addr, target_addr)
prev_ret = [0]
vip_log = []       # (r10, dword@r10)
callouts = []      # VM -> native transitions
prev_addr = [0]
VMSEG = (0x140025000, 0x140274000)

def on_code(uc, a, sz, ud):
    trace.append(a)
    p = prev_addr[0]
    if VMSEG[0] <= p < VMSEG[1] and not (VMSEG[0] <= a < VMSEG[1]):
        callouts.append((p, a, uc.reg_read(UC_X86_REG_RCX), uc.reg_read(UC_X86_REG_RDX),
                         uc.reg_read(UC_X86_REG_R8), uc.reg_read(UC_X86_REG_R9),
                         uc.reg_read(UC_X86_REG_RSP)))
    prev_addr[0] = a
    if prev_ret[0]:
        rets.append((prev_ret[0], a))
    try:
        b0 = uc.mem_read(a, 1)[0]
    except Exception:
        b0 = -1
    prev_ret[0] = a if b0 in (0xC3, 0xC2) else 0
    if len(trace) >= LIMIT:
        uc.emu_stop()
mu.hook_add(UC_HOOK_CODE, on_code)

def on_disp(uc, a, sz, ud):
    r10 = uc.reg_read(UC_X86_REG_R10)
    try:
        d = struct.unpack("<I", uc.mem_read(r10, 4))[0]
    except Exception:
        d = None
    vip_log.append((r10, d))
mu.hook_add(UC_HOOK_CODE, on_disp, begin=0x14003EE4E, end=0x14003EE4E)

disp_targets = []
steps = []
cur = [None]
VIP_LO, VIP_HI = 0x14001D000, 0x140021000
def on_jmpdi(uc, a, sz, ud):
    t = uc.reg_read(UC_X86_REG_RDI)
    r10 = uc.reg_read(UC_X86_REG_R10); r11 = uc.reg_read(UC_X86_REG_R11)
    disp_targets.append((a, t, r10, r11, uc.reg_read(UC_X86_REG_RBP), uc.reg_read(UC_X86_REG_RSP)))
    d = {"site": a, "h": t, "r10": r10, "r11": r11, "rd": [], "wr": [], "vi": []}
    steps.append(d); cur[0] = d
mu.hook_add(UC_HOOK_CODE, on_jmpdi, begin=0x14003EFA5, end=0x14003EFA5)
mu.hook_add(UC_HOOK_CODE, on_jmpdi, begin=0x140025279, end=0x140025279)

def on_read(uc, access, addr, size, val, ud):
    d = cur[0]
    if d is None:
        return
    if VIP_LO <= addr < VIP_HI:
        d["vi"].append((addr, size, val))
    elif d["r11"] - 0x100 <= addr <= d["r11"] + 0x400:
        d["rd"].append((addr, size, val))
def on_write(uc, access, addr, size, val, ud):
    d = cur[0]
    if d is None:
        return
    if d["r11"] - 0x100 <= addr <= d["r11"] + 0x400:
        d["wr"].append((addr, size, val))
mu.hook_add(UC_HOOK_MEM_READ, on_read)
mu.hook_add(UC_HOOK_MEM_WRITE, on_write)

try:
    mu.emu_start(START, 0, count=LIMIT)
    print("emu_start returned without exception")
except UcError as e:
    print("UC ERROR:", e, "rip=", hex(mu.reg_read(UC_X86_REG_RIP)))
    for nm, r in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),("rcx",UC_X86_REG_RCX),
                  ("rdx",UC_X86_REG_RDX),("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
                  ("rbp",UC_X86_REG_RBP),("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
                  ("r10",UC_X86_REG_R10),("r11",UC_X86_REG_R11),("r12",UC_X86_REG_R12),
                  ("r13",UC_X86_REG_R13),("r14",UC_X86_REG_R14),("r15",UC_X86_REG_R15)):
        print("   %s=%x" % (nm, mu.reg_read(r)))
except Exception as e:
    print("PY ERROR:", e)
    traceback.print_exc()

print("executed", len(trace), "instructions")
print("rsp=", hex(mu.reg_read(UC_X86_REG_RSP)), "rbx=", hex(mu.reg_read(UC_X86_REG_RBX)),
      "r10=", hex(mu.reg_read(UC_X86_REG_R10)), "rdi=", hex(mu.reg_read(UC_X86_REG_RDI)))
print("last 50 addrs:")
for a in trace[-50:]:
    print("  ", hex(a))

VM_LO, VM_HI = 0x140025000, 0x140274000
invm = sum(1 for a in trace if VM_LO <= a < VM_HI)
print("in-VM insns:", invm, "/", len(trace))
print("hit dispatcher 0x14003EE4E:", 0x14003EE4E in trace)
print("hit vm_entry 0x1401FC653:", 0x1401FC653 in trace)
print("api calls:", api_calls[:40])
print("ret events:", len(rets))
print("dispatch iterations:", len(vip_log))
print("jmp-rdi dispatches:", len(disp_targets))
print("VM->native callouts:", len(callouts))
for p, t, rcx, rdx, r8, r9, rsp in callouts:
    print("   %x -> %x  rcx=%x rdx=%x r8=%x r9=%x" % (p, t, rcx, rdx, r8, r9))
print("handler sequence:")
for s, t, r10, r11, rbp, rsp in disp_targets:
    print("   -> %x   r10=%x r11=%x rbp=%x rsp=%x" % (t, r10, r11, rbp, rsp))
with open(TRACE_FILE.replace("trace", "handlers"), "w") as f:
    for s, t, r10, r11, rbp, rsp in disp_targets:
        f.write("%x\n" % t)
with open(TRACE_FILE.replace("trace", "handler_ctx"), "w") as f:
    for s, t, r10, r11, rbp, rsp in disp_targets:
        f.write("%x %x %x %x %x %x\n" % (s, t, r10, r11, rbp, rsp))
with open(TRACE_FILE.replace("trace", "steps"), "w") as f:
    for i, d in enumerate(steps):
        f.write("STEP %d site=%x h=%x r10=%x r11=%x\n" % (i, d["site"], d["h"], d["r10"], d["r11"]))
        for a, s, v in d["rd"]:
            f.write("  RD %x %d %x\n" % (a, s, v))
        for a, s, v in d["wr"]:
            f.write("  WR %x %d %x\n" % (a, s, v))
        for a, s, v in d["vi"]:
            f.write("  VI %x %d %x\n" % (a, s, v))
with open(TRACE_FILE, "w") as f:
    for a in trace:
        f.write("%x\n" % a)
with open(TRACE_FILE.replace("trace", "rets"), "w") as f:
    for o, t in rets:
        f.write("%x %x\n" % (o, t))
with open(TRACE_FILE.replace("trace", "vip"), "w") as f:
    for r, d in vip_log:
        f.write("%x %s\n" % (r, "%x" % d if d is not None else "?"))
print("trace ->", TRACE_FILE)

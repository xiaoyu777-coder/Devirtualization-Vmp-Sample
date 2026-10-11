import pefile, struct
from capstone import *

IB = 0x140000000
SRC = "VMPTestAndResearch.vmp.exe"
OUT = "VMPTestAndResearch.devirt.exe"

# targets recovered from the VM trace
COUT_IAT   = 0x140021108
MSGBOX_IAT = 0x1400211E0
OP_LSHIFT  = 0x140011348
MAIN_VA    = 0x140012380

pe = pefile.PE(SRC)
sec_align  = pe.OPTIONAL_HEADER.SectionAlignment
file_align = pe.OPTIONAL_HEADER.FileAlignment
last_end = max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections)
new_rva = (last_end + sec_align - 1) // sec_align * sec_align
new_va  = IB + new_rva

code = bytearray()
fix = []

def emit(b):
    code.extend(b)

def ripfix(kind, target):
    off = len(code)
    code.extend(b"\x00\x00\x00\x00")
    fix.append((off, kind, target))

emit(b"\x48\x83\xEC\x28")                  # sub  rsp, 0x28
emit(b"\x48\x8B\x0D"); ripfix("abs", COUT_IAT)
emit(b"\x48\x8D\x15"); ripfix("str", "hello")
emit(b"\xE8");         ripfix("abs", OP_LSHIFT)
emit(b"\x31\xC9")                          # xor  ecx, ecx
emit(b"\x48\x8D\x15"); ripfix("str", "text")
emit(b"\x4C\x8D\x05"); ripfix("str", "caption")
emit(b"\x45\x31\xC9")                      # xor  r9d, r9d
emit(b"\xFF\x15");     ripfix("abs", MSGBOX_IAT)
emit(b"\x31\xC0")                          # xor  eax, eax
emit(b"\x48\x83\xC4\x28")                  # add  rsp, 0x28
emit(b"\xC3")                              # ret

hello   = b"Hello World!\n\x00"
caption = "Message".encode("utf-16-le") + b"\x00\x00"
text    = "Hello, World!".encode("utf-16-le") + b"\x00\x00"

off_hello = (len(code) + 15) // 16 * 16
off_caption = (off_hello + len(hello) + 1) // 2 * 2
off_text = (off_caption + len(caption) + 1) // 2 * 2
total = off_text + len(text)
str_va = {"hello": new_va + off_hello, "caption": new_va + off_caption, "text": new_va + off_text}

sec_data = bytearray(total)
sec_data[off_hello:off_hello+len(hello)] = hello
sec_data[off_caption:off_caption+len(caption)] = caption
sec_data[off_text:off_text+len(text)] = text

for off, kind, target in fix:
    tgt = target if kind == "abs" else str_va[target]
    code[off:off+4] = struct.pack("<i", tgt - (new_va + off + 4))
sec_data[:len(code)] = code

print("new section .devirt VA=%x size=%d (code %d bytes)" % (new_va, total, len(code)))
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(bytes(sec_data[:len(code)]), new_va):
    print("   %x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

raw = bytearray(open(SRC, "rb").read())
e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
nsec_off = e_lfanew + 6
opt_off  = e_lfanew + 24
size_opt = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
assert struct.unpack_from("<H", raw, opt_off)[0] == 0x20B
size_of_image_off = opt_off + 56
size_of_hdr_off   = opt_off + 60
nsec = struct.unpack_from("<H", raw, nsec_off)[0]
size_of_hdr = struct.unpack_from("<I", raw, size_of_hdr_off)[0]
hdr_end = opt_off + size_opt + nsec * 40
assert hdr_end + 40 <= size_of_hdr, "no room for new section header"

new_raw = (len(raw) + file_align - 1) // file_align * file_align
raw += b"\x00" * (new_raw - len(raw))
raw += sec_data
raw += b"\x00" * ((file_align - total % file_align) % file_align)

hdr = bytearray(40)
hdr[0:8] = b".devirt\x00"
struct.pack_into("<I", hdr,  8, total)
struct.pack_into("<I", hdr, 12, new_rva)
struct.pack_into("<I", hdr, 16, (total + file_align - 1)//file_align*file_align)
struct.pack_into("<I", hdr, 20, new_raw)
struct.pack_into("<I", hdr, 36, 0x60000020)
raw[hdr_end:hdr_end+40] = hdr
struct.pack_into("<H", raw, nsec_off, nsec + 1)
struct.pack_into("<I", raw, size_of_image_off,
                 (new_rva + total + sec_align - 1)//sec_align*sec_align)

def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise KeyError(hex(rva))

mo = rva_to_off(MAIN_VA - IB)
struct.pack_into("<Bi", raw, mo, 0xE9, new_va - (MAIN_VA + 5))
print("patched main %x: jmp %x" % (MAIN_VA, new_va))

open(OUT, "wb").write(raw)
print("wrote", OUT)

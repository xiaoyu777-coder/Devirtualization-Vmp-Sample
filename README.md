# Devirtualization-Vmp-Sample
VMProtect Research By Deepseek

Source code:

<img width="1422" height="748" alt="image" src="https://github.com/user-attachments/assets/20c5cbb3-897f-4520-8889-305022c36a08" />

Before:

<img width="1303" height="240" alt="image" src="https://github.com/user-attachments/assets/c8be70d4-e64a-4923-9448-1a5a207dd905" />

<img width="1201" height="389" alt="image" src="https://github.com/user-attachments/assets/14f7cd04-85e1-49a8-8554-3e85c6728a82" />

<img width="1588" height="892" alt="image" src="https://github.com/user-attachments/assets/1ce53d3c-905e-41ed-8795-15d4cbf89abe" />


Effects:

<img width="1332" height="212" alt="image" src="https://github.com/user-attachments/assets/a1272358-a7af-4f25-8820-0c6ea7e836aa" />

<img width="1767" height="487" alt="image" src="https://github.com/user-attachments/assets/f61ae28d-5b9d-4ce9-881c-5b2dab3a7f39" />



Sample: `VMPTestAndResearch.vmp.exe`, image base `0x140000000`, x64 / MSVC Debug.  
Goal: Locate `main` → find `vm_entry` and the VM dispatcher/handlers → run it under Unicorn → lift native code from the trace → write it into a new section while remaining ASLR-safe → verify.

---

## 0. Environment and Artifacts

| Role | Tools |
|---|---|
| Static analysis | IDA Pro 9.4 + ida-pro-mcp |
| Emulation / tracing | Python 3.11 + unicorn 2.1.2 + capstone 6.0.0 |
| PE handling | pefile |
| Assembly | keystone 0.9.2 |

Artifacts produced in this directory:

| File | Purpose |
|---|---|
| `vmtrace.py` | Unicorn emulation + per-instruction / per-handler tracing |
| `disasm.py` / `classify.py` / `classify2.py` | Capstone disassembly of arbitrary addresses / handlers |
| `lift.py` | Lift the trace into readable pseudo-assembly (`lift.txt`) |
| `devirt_inject.py` | Generate recovered code + inject `.devirt` section + hook `main` |
| `devirt_verify.py` | Behavioral verification of the devirtualized EXE |
| `trace.txt` / `handlers.txt` / `handler_ctx.txt` / `steps.txt` / `rets.txt` / `vip.txt` / `out.txt` | Intermediate data |
| `VMPTestAndResearch.devirt.exe` | Devirtualized output |

---

## 1. Static Reconnaissance: Pinpoint `main`, `vm_entry`, and the Dispatcher

### 1.1 `main` is merely a stub that enters the VM

```
0x140012380  main:
             call loc_1401FC653          ; only meaningful instruction
0x140012385  (rcl dword ptr cs:..., cl)  ; data / JUMPOUT; function ends here
```

In other words, the body of `main` has already been virtualized; control flow is immediately redirected into the VM section.

### 1.2 `vm_entry` = `0x1401FC653`

```asm
1401FC653  pushfq
1401FC654  add  qword ptr [rsp+8], 0FFFFFFFFBFFEDC7Bh
1401FC65D  mov  qword ptr [rsp+8], 0FFFFFFFFB3153121h
1401FC666  push qword ptr [rsp+0]
1401FC66A  popfq
1401FC66B  lea  rsp, [rsp+8]
1401FC670  call loc_14003ECAD            ; -> VM dispatcher
1401FC675  <garbage bytes; no normal return>
```

The only xref to `0x1401FC653` is from `main` (call type), which matches the signature of a “VM entry stub.”  
A cluster of similar stubs was also found (`0x1401FC5C4` / `0x1401FC653` …); they differ only in the `0xB3153xxx` constant.

### 1.3 Dispatcher and VM section

- The call target `0x14003ECAD` lands in the `.ZR(` section (Section 9 in the IDB):  
  `0x140025000 – 0x140274000`, roughly 2.4 MB, executable.
- IDA collapses almost the entire section into one giant function `sub_140025000` (~1.93 MB) and recognizes only 105 basic blocks.  
  **Never call `decompile`/`disasm` on `sub_140025000` from IDAPython, and never call `ida_auto.auto_wait()`**  
  (VMProtect’s `call $+5` / overlapping instructions cause the auto-analyzer to keep flipping judgments and never converge, which times out the MCP).
- `0x14003EE4E` is (the first) dispatcher loop head.

---

## 2. Handler Dispatch Mechanism

### 2.1 Dispatch primitive (`push`/`ret` computed jump)

```
0x14003EE4E  r8d = [r10]              ; fetch encoded delta from VIP
             decode(r8d, key=rbp)     ; bswap / sbb / rol 2 / inc / neg
             rbp ^= r8                ; rolling key update
             rdi = 0x14003EE4E + r8   ; next handler
             mov [rsp+..], rdi ; retn ; push+ret to jump there
```

Conclusion: **`handler = 0x14003EE4E + decode32([r10])`**, where `r10` = VIP and `rbp` = the rolling key updated on every step.

### 2.2 Shared tail-dispatch epilogue (`0x140027855`)

```
ror r9d,1 ; and r8b,r8b ; lea r9d,[r8+r9+72D73F3h] ; not r9d ; xor r10,r9
movsxd r9,r9d ; call $+5 ; add rdi,r9
mov [rsp+..], r8 ; neg dword [rsp+..] ; mov [rsp+..], rdi ; retn
```

Handlers jump among themselves solely via this “decrypt next delta + push/ret” scheme, so  
**there is never a direct `jmp 0x14003EE4E`**. Static xref enumeration cannot discover the handlers.

### 2.3 VM stack exit (`0x140036579`)

```
lea r10, [rsp+50h+arg_140] ; cmp rdi, r10 ; ja <exit>   ; VM stack overflow -> native call / exit
```

---

## 3. Building the Unicorn Emulator

Core steps of `vmtrace.py`:

1. **Map the image**: Read sections with `pefile`, `mem_map(0x140000000, SizeOfImage)`, write the header and every section.
2. **Stack**: Allocate a large stack (the VM does `mov rsp, rax` for stack switching) and place `rsp` in the middle.
3. **TEB/PEB**: Map one page as a fake TEB, point `gs_base` at it, set `PEB.BeingDebugged=0` to avoid anti-debug page faults.
4. **Import stubs**: Parse the import table and write each IAT slot as `0x50000000 + i*8`. On a hit, log the call and “return” (`rsp+=8; rax=0; rip=ret`).
5. **Fake `std::cout`**: `?cout@std@@` is a data import. Point it at a zeroed object page whose first field points to a valid memory page; otherwise native ostream code will dereference a bogus pointer and crash.
6. **Start execution**: `emu_start(0x1401FC653, 0, count=600000)`.

Result: `emu_start` returns **without exception**. Total instructions: 29 002, of which **28 558 are inside the VM section**. The native call sequence matches the source semantics (`strlen` / MSVCP ostream / `MessageBoxW`).

---

## 4. Collecting the Trace

### 4.1 Instruction trace

`UC_HOOK_CODE` records every RIP → `trace.txt`.

### 4.2 Handler sequence (critical)

The main dispatcher performs `jmp rdi` at `0x14003EFA5` (`rdi` holds the next handler).  
Hooks at `0x14003EFA5` and `0x140025279` read `rdi` and produce a **113-step handler sequence** (`handlers.txt`).

```
113 dispatches / 88 distinct handlers (VMProtect generates multiple mutated copies per opcode)
Most frequent handler 0x1401F8DA3 used 6 times
```

### 4.3 Per-step context

Record `r10` (VIP) / `r11` (VM register base) / `rbp` (key) at every step → `handler_ctx.txt`.

### 4.4 VM ↔ native call boundaries

Inside `UC_HOOK_CODE`, detect transitions “previous RIP in VM section, current RIP not in VM section,” record the target plus `rcx/rdx/r8/r9` → obtain what `main` actually called.

---

## 5. Key Discoveries

### 5.1 VM bytecode lives in `.pdata`

`r10` (VIP) starts at `0x14001E452` and increments; it falls inside `0x14001E000–0x140021000` (the exception directory `.pdata`).  
VMProtect placed the bytecode in `.pdata`.

### 5.2 VM register area is on the stack

`r11 ≈ 0x6FFFF000` and moves with each step; `[r11]`, `[r11+8]`, … are the VM register slots.

### 5.3 Native call sequence = true semantics of `main`

```
0x140047803 -> 0x140011348   rcx=cout  rdx=0x14001AC28   ; operator<<(cout, "Hello World!\n")
0x1401FC5D9 -> ...           rcx=0     rdx=0x14001AC50   r8=0x14001AC38  ; MessageBoxW(NULL, L"Hello, World!", L"Message", 0)
```

Corresponding strings (`.rdata`):

| VA | Content |
|---|---|
| `0x14001AC28` | `"Hello World!\n"` |
| `0x14001AC38` | `L"Message"` |
| `0x14001AC50` | `L"Hello, World!"` |

Callees:

| VA | Name |
|---|---|
| `0x140011348` | `std::operator<<(ostream&, const char*)` thunk |
| `0x140021108` | `__imp_?cout@std@@` (data import) |
| `0x1400211E0` | `__imp_MessageBoxW` |
| `0x140011424` | `_CheckForDebuggerJustMyCode` (Debug-build JMC check; ignorable) |

---

## 6. Code Generation (RIP-relative, ASLR-safe)

`devirt_inject.py` hand-encodes the recovered `main`, **using only RIP-relative / rel32 addressing; never absolute addresses**:

```asm
sub  rsp, 0x28                 ; 48 83 EC 28
mov  rcx, [rip + d1]           ; 48 8B 0D d1        -> 0x140021108 (cout IAT)
lea  rdx, [rip + d2]           ; 48 8D 15 d2        -> "Hello World!\n"
call 0x140011348               ; E8 d3              -> operator<<
xor  ecx, ecx                  ; 31 C9
lea  rdx, [rip + d4]           ; 48 8D 15 d4        -> L"Hello, World!"
lea  r8,  [rip + d5]           ; 4C 8D 05 d5        -> L"Message"
xor  r9d, r9d                  ; 45 31 C9
call [rip + d6]                ; FF 15 d6           -> 0x1400211E0 (MessageBoxW IAT)
xor  eax, eax                  ; 31 C0
add  rsp, 0x28                 ; 48 83 C4 28
ret                            ; C3
```

The generator uses a fixup table: each RIP-relative instruction is first emitted with a 4-byte zero placeholder; after the final location is known the displacement is filled in as `disp32 = target - (insn_end)`.  
Strings (one narrow string + two wide strings) are inlined inside the new section so the `lea`s point to them, making the code self-contained.

---

## 7. Injecting the New Section `.devirt`

The PE is modified by hand (more controllable than `pefile.add_section`):

1. `new_rva = align(last_section.VirtualAddress + Size, SectionAlignment)`; `new_va = 0x140000000 + new_rva`.
2. Append a 40-byte section header at the end of the section table: name `.devirt`, VirtualSize / VirtualAddress / SizeOfRawData / PointerToRawData, `Characteristics = 0x60000020` (CODE|EXECUTE|READ).
3. Append the section data at the end of the file, aligned to `FileAlignment`.
4. `NumberOfSections += 1`, `SizeOfImage = align(new_rva + size, SectionAlignment)`.
5. Hook: rewrite `main` (`0x140012380`) as `jmp .devirt` (`E9 rel32`).

Result of this run: `.devirt` VA `0x140276000`, 122 bytes, `SizeOfImage → 0x277000`,  
`main` patched to `jmp 0x140276000`.

---

## 8. Verification

`devirt_verify.py` maps the patched EXE, stubs imports, and runs `emu_start(0x140012380)`.

```
devirt main ran OK
api calls: [ucrtbased!strlen, MSVCP140D!?width/?rdbuf/?good/?setstate/?uncaught_exceptions/?_Osfx, USER32!MessageBoxW]
rax (ret val): 0
```

Behavior, call sequence, and return value are **identical** to the original virtualized program.

---

## 9. Relocation / ASLR Considerations

- **Use only RIP-relative addressing**: `[rip+disp32]` / `call rel32`. Zero absolute addresses in the code → the image still works correctly after ASLR relocates it; **no `.reloc` entries are required**.
- If absolute immediates were used (`mov rax, 0x140021108`) you would have to add `IMAGE_REL_BASED_DIR64` entries to `.reloc`; otherwise the binary would crash under ASLR.
- The new section is < 2 GB away from `.text` / `.idata` / `.rsrc`, so `rel32` does not overflow and RIP-relative addressing remains safe.
- At the instruction level: `sal/shl` versus `shr/sar` (LLVM’s `shl` / `lshr` / `ashr`) keep their operand width and `cl` count; RIP-relativizing them does not change semantics—simply preserve the original encoding.

---

## 10. Reproduction Commands

```powershell
cd D:\Code\VSS\VMPTestAndResearch\x64\Debug

# 1) Emulate + trace (fake cout / stub imports)
python vmtrace.py 600000

# 2) Lift trace -> pseudo-assembly
python lift.py            # -> lift.txt

# 3) Generate recovered code + inject new section + hook main
python devirt_inject.py   # -> VMPTestAndResearch.devirt.exe

# 4) Verify
python devirt_verify.py
```

---

## 11. Limitations and Possible Extensions

- The recovered code is a **semantically equivalent** `main` (it calls the original `operator<<` thunk and the two imports); it is not a byte-for-byte reconstruction of the compiler’s original output. Strings are inlined in the new section.
- For a fully automated general-purpose devirtualizer: turn “call-out extraction + per-step VM register read/write + handler semantic probing” into a generic pass that can emit RIP-relative code for any virtualized function and inject it into a new section.
- Handler semantics are currently determined by manual inspection plus runtime observation (`lift.py`’s arithmetic inference). VMProtect’s mutated copies introduce noise; “isolated probing” (run a single handler with controlled initial VM-register values) is needed to name them definitively.

import sys, collections, re

STEPS = r"D:\Code\VSS\VMPTestAndResearch\x64\Debug\steps.txt"
M = (1 << 64) - 1

steps = []
cur = None
for line in open(STEPS):
    line = line.rstrip("\n")
    if line.startswith("STEP "):
        site = int(re.search(r"site=([0-9a-f]+)", line).group(1), 16)
        h = int(re.search(r"h=([0-9a-f]+)", line).group(1), 16)
        r10 = int(re.search(r"r10=([0-9a-f]+)", line).group(1), 16)
        r11 = int(re.search(r"r11=([0-9a-f]+)", line).group(1), 16)
        cur = {"site": site, "h": h, "r10": r10, "r11": r11, "rd": [], "wr": [], "vi": []}
        steps.append(cur)
    elif line.strip().startswith(("RD", "WR", "VI")):
        k, a, s, v = line.split()
        cur[{"RD": "rd", "WR": "wr", "VI": "vi"}[k]].append((int(a, 16), int(s), int(v, 16)))

OPS = {
    "ADD": lambda a, b: (a + b) & M,
    "SUB": lambda a, b: (a - b) & M,
    "XOR": lambda a, b: a ^ b,
    "AND": lambda a, b: a & b,
    "OR":  lambda a, b: a | b,
    "ADC": lambda a, b: (a + b + 1) & M,
    "SBB": lambda a, b: (a - b - 1) & M,
}

def infer(d):
    reads = []
    seen = set()
    for a, s, v in d["rd"]:
        if s == 8 and (a, v) not in seen:
            seen.add((a, v)); reads.append(v)
    for a, s, v in d["wr"]:
        if s != 8:
            continue
        for r1 in reads:
            for name, f in OPS.items():
                if f(r1, 0) == v and name in ("ADD", "SUB", "XOR", "AND", "OR"):
                    return "%s r,%s" % (name, hex(r1))
            if (~r1 & M) == v:
                return "NOT"
            if (r1 << 1) & M == v:
                return "SHL r,1"
            if (r1 >> 1) == v:
                return "SHR r,1"
    for a, s, v in d["wr"]:
        for a2, s2, v2 in d["rd"]:
            if s == 8 and s2 == 8:
                for r3 in reads:
                    for name, f in OPS.items():
                        if f(v2, r3) == v:
                            return name
    return ""

FAM = {
    0x1401F1997: "ADD", 0x1401F21F3: "ADD", 0x1401F24CC: "ADD", 0x1401F265B: "ADD",
    0x1401F1800: "IMM/PUSH", 0x1401F11B7: "IMM/PUSH",
}
SITE = {0x14003EFA5: "main-disp", 0x140025279: "tramp-disp"}
print("#  site      handler     vip        byt  fam        vmreg(=value)")
prev = None
for i, d in enumerate(steps):
    n = 0 if (prev is None or prev[0] != d["site"]) else d["r10"] - prev[1]
    prev = (d["site"], d["r10"])
    wr = []
    for a, s, v in d["wr"]:
        if s == 8 and d["r11"] - 0x100 <= a <= d["r11"] + 0x400:
            wr.append("[r11%+d]=%x" % (a - d["r11"], v))
    print("%3d %-9s %-11s %-10x %-4d %-10s %s" % (
        i, SITE.get(d["site"], "%x" % d["site"]), "%x" % d["h"], d["r10"], n,
        FAM.get(d["h"], ""), " ".join(wr[:4])))

#!/usr/bin/env python3
"""Disassemble the challenge 03 bytecode and invert the password check.

Usage: python3 vm_solve.py <path to 03-tiny-vm> [--disasm]

The script locates the "TVM1" image inside the binary, decodes it with the
instruction set recovered in Ghidra, and solves each per-character check:

    rol8(input[i] ^ k, n) + c == target   =>   input[i] = ror8(target - c, n) ^ k
"""
import struct
import sys

OPS = {
    0x10: ("LDI", "rb"), 0x11: ("LDC", "rb"), 0x20: ("XOR", "rr"),
    0x21: ("ADD", "rr"), 0x22: ("ROL", "rb"), 0x30: ("CMP", "rr"),
    0x40: ("JNE", "a"), 0x41: ("JMP", "a"), 0x50: ("LEN", "r"),
    0xF0: ("OK", ""), 0xFF: ("FAIL", ""),
}
SIZES = {"rb": 3, "rr": 3, "a": 3, "r": 2, "": 1}


def ror8(v: int, n: int) -> int:
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF


def load_image(path: str) -> bytes:
    data = open(path, "rb").read()
    # The magic also exists as the "TVM1" literal passed to memcmp, so skip
    # any hit whose header does not look like a real image.
    off = data.find(b"TVM1")
    while off >= 0:
        (length,) = struct.unpack_from("<H", data, off + 4)
        if 0 < length and off + 6 + length <= len(data) and data[off + 6] in OPS:
            return data[off + 6: off + 6 + length]
        off = data.find(b"TVM1", off + 1)
    sys.exit("no TVM1 image found")


def disassemble(code: bytes):
    pc, out = 0, []
    while pc < len(code):
        mn, fmt = OPS.get(code[pc], (f"DB 0x{code[pc]:02x}", ""))
        size = SIZES[fmt]
        ops = code[pc + 1: pc + size]
        if fmt == "rb":
            text = f"r{ops[0]}, 0x{ops[1]:02x}"
        elif fmt == "rr":
            text = f"r{ops[0]}, r{ops[1]}"
        elif fmt == "a":
            text = f"0x{struct.unpack('<H', ops)[0]:04x}"
        elif fmt == "r":
            text = f"r{ops[0]}"
        else:
            text = ""
        out.append((pc, mn, list(ops), text))
        pc += size
    return out


def solve(insns) -> str:
    """Match the 9-instruction per-character block and invert it."""
    chars = {}
    for i in range(len(insns) - 8):
        block = [x[1] for x in insns[i:i + 9]]
        if block != ["LDC", "LDI", "XOR", "ROL", "LDI", "ADD", "LDI", "CMP", "JNE"]:
            continue
        idx = insns[i][2][1]
        k = insns[i + 1][2][1]
        n = insns[i + 3][2][1]
        c = insns[i + 4][2][1]
        target = insns[i + 6][2][1]
        chars[idx] = chr(ror8((target - c) & 0xFF, n) ^ k)
    return "".join(chars[i] for i in sorted(chars))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: vm_solve.py <03-tiny-vm> [--disasm]")
    insns = disassemble(load_image(sys.argv[1]))
    if "--disasm" in sys.argv:
        for pc, mn, _, text in insns:
            print(f"{pc:04x}  {mn:<5}{text}")
    print(solve(insns))

#!/usr/bin/env python3
"""Key generator for challenge 01, rebuilt from the Ghidra analysis.

Usage: python3 keygen.py <name>
"""
import sys

MASK32 = 0xFFFFFFFF


def rol32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & MASK32


def name_hash(name: bytes) -> int:
    h = 0x1337C0DE
    for c in name:
        h ^= ord(chr(c).upper()) if 0x61 <= c <= 0x7A else c
        h = rol32(h, 5)
        h = (h * 0x01000193) & MASK32
    return h


def name_checksum(name: bytes) -> int:
    total = sum(c * (i + 1) for i, c in enumerate(name)) & MASK32
    return (total * len(name)) & 0xFFFF


def serial_for(name: str) -> str:
    raw = name.encode()
    if not 4 <= len(raw) <= 32:
        raise ValueError("name must be 4 to 32 bytes")
    h = name_hash(raw)
    a, b = h >> 16, h & 0xFFFF
    c = a ^ b ^ 0xBEEF
    d = name_checksum(raw)
    return "-".join(f"{p:04X}" for p in (a, b, c, d))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: keygen.py <name>")
    print(serial_for(sys.argv[1]))

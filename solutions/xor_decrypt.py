#!/usr/bin/env python3
"""Decrypt one string from challenge 02 by hand.

Copy the encrypted bytes and the key out of Ghidra, then:

    python3 xor_decrypt.py <key> <hex bytes>
    python3 xor_decrypt.py 0xc3 "b0 ce 37 ..."

ghidra_scripts/DecryptStrings.java does the same thing for every call site
automatically.
"""
import sys

STEP = 0x1F


def decrypt(blob: bytes, key: int) -> str:
    return bytes(b ^ ((key + i * STEP) & 0xFF) for i, b in enumerate(blob)).decode(errors="replace")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: xor_decrypt.py <key> <hex bytes>")
    key = int(sys.argv[1], 0)
    blob = bytes.fromhex("".join(sys.argv[2:]).replace("0x", "").replace(",", ""))
    print(decrypt(blob, key))

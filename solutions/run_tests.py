#!/usr/bin/env python3
"""Run every challenge binary against its solution.

Usage: python3 solutions/run_tests.py <dir with binaries>
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import keygen  # noqa: E402
import vm_solve  # noqa: E402
from xor_decrypt import decrypt  # noqa: E402


def run(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=10)


def main(bindir: str) -> int:
    failures = 0

    def check(label, ok, detail=""):
        nonlocal failures
        print(f"[{'PASS' if ok else 'FAIL'}] {label} {detail}")
        failures += 0 if ok else 1

    kg = os.path.join(bindir, "01-keygen")
    for name in ["tai", "Ghidra", "reverse_engineer", "ABCDabcd1234"]:
        try:
            serial = keygen.serial_for(name)
        except ValueError:
            r = run([kg, name, "0000-0000-0000-0000"])
            check(f"01 rejects short name {name!r}", r.returncode == 1)
            continue
        r = run([kg, name, serial])
        check(f"01 keygen {name!r}", r.returncode == 0, serial)
    r = run([kg, "Ghidra", "0000-0000-0000-0000"])
    check("01 rejects bad serial", r.returncode == 1)

    hs = os.path.join(bindir, "02-hidden-strings")
    blob = bytes.fromhex("b09232434b2c08f196ea8e741a61")
    password = decrypt(blob, 0xC3)
    r = run([hs], stdin=password + "\n")
    check("02 password", r.returncode == 0 and "GT{" in r.stdout, r.stdout.strip())
    r = run([hs], stdin="hunter2\n")
    check("02 decoy rejected", r.returncode == 1)

    vm = os.path.join(bindir, "03-tiny-vm")
    pw = vm_solve.solve(vm_solve.disassemble(vm_solve.load_image(vm)))
    r = run([vm, pw])
    check("03 vm password", r.returncode == 0, r.stdout.strip())
    r = run([vm, "Ph4s3_Sh1ft?"])
    check("03 near miss rejected", r.returncode == 1)

    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "bin"))

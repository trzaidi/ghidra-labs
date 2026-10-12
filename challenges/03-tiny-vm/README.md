# 03: tiny VM

```
./03-tiny-vm <password>
```

The password check runs as bytecode on a small virtual machine embedded in
the binary.

Goals

1. Recover the VM state structure and type it in Ghidra.
2. Recover the instruction set from the dispatch switch.
3. Disassemble the bytecode with a Ghidra script.
4. Invert the check to recover the password and the flag.

Binary: `bin/03-tiny-vm`. Walkthrough: [writeups/03-tiny-vm.md](../../writeups/03-tiny-vm.md).

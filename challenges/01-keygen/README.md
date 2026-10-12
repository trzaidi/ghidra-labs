# 01: keygen

```
./01-keygen <name> <serial>
```

The program accepts a name and a serial and says whether the serial is
valid for that name.

Goals

1. Find the serial check in Ghidra and recover the algorithm.
2. Write a key generator that outputs a valid serial for any name.
3. Patch the binary so it accepts every serial.

Binary: `bin/01-keygen`. Walkthrough: [writeups/01-keygen.md](../../writeups/01-keygen.md).

# 02: hidden strings

```
./02-hidden-strings
```

The program asks for an access code. Running `strings` on it will not
give you the answer.

Goals

1. Work out how the program hides its strings.
2. Recover every hidden string statically, without running the binary.
3. Automate step 2 with a Ghidra script.

Binary: `bin/02-hidden-strings`. Walkthrough: [writeups/02-hidden-strings.md](../../writeups/02-hidden-strings.md).

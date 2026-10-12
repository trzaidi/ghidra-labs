# 02: hidden strings walkthrough

Binary: `bin/02-hidden-strings` (stripped, non-PIE, base `0x400000`).

## 1. The obvious strings are a trap

```
$ strings -n 6 bin/02-hidden-strings | grep -i pass
debug_password=hunter2
```

`hunter2` is rejected. In Ghidra, Defined Strings shows that string has no
code references at all: select it and Show References returns nothing. It
is a decoy. The prompt, the access code, and the flag do not appear as
strings anywhere.

## 2. Find the routine that builds strings

Label `main` (`0x4011fc`, recovered from the entry stub as in challenge 01).
The decompiler shows the same callee five times with a stack buffer, a
global address, a small integer, and a byte:

```c
FUN_004011d6(local_48, &DAT_00402080, 0x13, 0x5a);
fputs(local_48, stdout);
...
FUN_004011d6(local_c8, &DAT_00402068, 0xe, 0xc3);
iVar1 = strcmp(local_88, local_c8);
```

The second call's output feeds `strcmp` against user input, so it builds
the access code.

## 3. Reverse the routine

`FUN_004011d6` is 38 bytes:

```
004011e0  MOV  R8D, ECX
004011e3  XOR  R8B, byte ptr [RSI + RAX*1]
004011e7  MOV  byte ptr [RDI + RAX*1], R8B
004011eb  ADD  RAX, 0x1
004011ef  ADD  ECX, 0x1f
004011f2  CMP  RDX, RAX
004011f5  JNZ  0x004011e0
004011f7  MOV  byte ptr [RDI + RDX*1], 0x0
```

Each byte is XORed with a key that starts at the fourth argument and grows
by `0x1f` per byte, then the output is NUL-terminated. Set the signature
with `Ctrl+L` on the function name:

```c
void decrypt_string(char *dst, uchar *src, ulong len, uchar key)
```

Every call site in `main` now reads cleanly, and the decompiler shows each
blob as `uchar *`.

## 4. Decrypt one by hand

Select `DAT_00402068`, set it to a 14-byte array (`[` then length 14), and
copy the bytes with Copy Special > Byte String:

```
$ python3 solutions/xor_decrypt.py 0xc3 "b0 92 32 43 4b 2c 08 f1 96 ea 8e 74 1a 61"
sp3ctrum-0wl-7
```

## 5. Decrypt all of them with a script

[ghidra_scripts/DecryptStrings.java](../ghidra_scripts/DecryptStrings.java)
does steps 2 to 4 for the whole program:

1. Finds the routine by heuristic: small, contains a loop with a XOR from
   memory, and has at least three callers.
2. Applies the signature above with `Function.replaceParameters`, so the
   decompiler assigns the four arguments to `RDI`, `RSI`, `RDX`, `CL`.
3. Decompiles each caller and walks the `HighFunction` P-code for `CALL`
   ops that target the routine. The constant `src`, `len`, and `key` inputs
   are read from the varnodes, following `COPY`, `CAST`, and `PTRSUB` when
   the decompiler wraps a global address.
4. Decrypts each blob, labels it `enc_<text>`, sets a plate comment on the
   blob and a pre-comment on the call site, and adds a bookmark.

Reading arguments from P-code instead of walking back through `MOV`
instructions means the script does not care which registers or instruction
order the compiler picked.

Output (Script Console, or `reports/02-hidden-strings-decrypted.txt` when
run headless):

```
Decryption routine: decrypt_string @ 004011d6
0040121f: src=00402080 len=19 key=0x5a -> "Enter access code: "
0040128a: src=00402068 len=14 key=0xc3 -> "sp3ctrum-0wl-7"
004012b9: src=00402020 len=14 key=0x41 -> "Access denied."
004012f2: src=00402050 len=22 key=0x17 -> "Access granted. Flag: "
00401322: src=00402030 len=25 key=0x8e -> "GT{x0r_1s_n0t_encrypt10n}"
Decrypted 5 string(s).
```

## 6. Confirm

```
$ echo sp3ctrum-0wl-7 | ./bin/02-hidden-strings
Enter access code: Access granted. Flag: GT{x0r_1s_n0t_encrypt10n}
```

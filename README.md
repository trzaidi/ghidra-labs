# ghidra-labs

Three reverse engineering challenges I wrote to practice and demonstrate
Ghidra, each with a full walkthrough, Ghidra scripts that automate the
analysis, and a headless pipeline that runs those scripts in CI.

| # | Challenge | Ghidra skills |
|---|---|---|
| 01 | [keygen](challenges/01-keygen) | strings and cross-references, renaming and retyping, reading the decompiler, recovering an algorithm, binary patching |
| 02 | [hidden-strings](challenges/02-hidden-strings) | spotting obfuscation, function signatures, decompiler P-code API, scripted string decryption |
| 03 | [tiny-vm](challenges/03-tiny-vm) | switch and jump table recovery, struct recovery, writing a bytecode disassembler script |

All binaries are stripped, non-PIE x86-64 Linux ELF files built with
`gcc -O1`. Prebuilt copies are in [bin/](bin) with checksums in
`bin/SHA256SUMS`, so the addresses in the writeups match what you see in
Ghidra.

## Layout

```
challenges/      C source for each challenge (spoilers)
bin/             stripped binaries to load into Ghidra
writeups/        step-by-step Ghidra walkthroughs (spoilers)
ghidra_scripts/  Ghidra Java scripts: Triage, DecryptStrings, VmDisassembler
solutions/       Python keygen and solvers, plus the test runner
scripts/         run_headless.sh, the analyzeHeadless pipeline
tools/           build-time generators for the encrypted strings and VM bytecode
```

## Try it

1. Install Ghidra ([docs/setup.md](docs/setup.md)).
2. Create a project and import the files in `bin/`.
3. Work each challenge before reading its writeup. The challenge READMEs
   state the goal without spoilers.

## Ghidra scripts

Add `ghidra_scripts/` in Script Manager (Manage Script Directories), then
run the scripts from the `GhidraLabs` category.

| Script | What it does |
|---|---|
| `Triage.java` | Writes a Markdown report of metadata, imports, functions by size, and strings. Recovers and labels `main` in stripped glibc binaries from the entry stub. |
| `DecryptStrings.java` | Finds the XOR string routine by heuristic, applies its signature, reads constant arguments at each call site from decompiler P-code, decrypts every string, and labels and comments the results. |
| `VmDisassembler.java` | Locates the `TVM1` bytecode image, disassembles it, and adds an EOL comment on every bytecode instruction in the Listing. |

## Headless analysis

```
scripts/run_headless.sh
```

The script imports each binary into a throwaway project, runs the scripts
through `analyzeHeadless`, writes reports to `reports/`, and checks for the
expected results. GitHub Actions runs the same pipeline on every push
against the latest Ghidra release and uploads the reports as an artifact.
See [.github/workflows/ghidra.yml](.github/workflows/ghidra.yml).

## Building

The committed binaries are all you need. To rebuild:

```
make release test        # on Linux x86-64
make docker              # on macOS, builds inside a linux/amd64 container
```

## License

MIT. See [LICENSE](LICENSE).

# Setup

## macOS (Apple Silicon or Intel)

Ghidra is a Homebrew formula, not a cask:

```
brew install ghidra
ghidraRun
```

The formula pulls in `openjdk@21`. To check the native decompiler works,
open any binary, let auto-analysis finish, and click a function. C code
should appear in the Decompile window.

## Linux

Download the latest `ghidra_*_PUBLIC_*.zip` from
https://github.com/NationalSecurityAgency/ghidra/releases, install JDK 21,
then:

```
unzip ghidra_*_PUBLIC_*.zip
./ghidra_*_PUBLIC/ghidraRun
```

## Loading the scripts

1. Window > Script Manager.
2. Click the Manage Script Directories icon and add this repo's
   `ghidra_scripts/` directory.
3. The scripts appear under the `GhidraLabs` category.

## Running headless

`scripts/run_headless.sh` finds `analyzeHeadless` through
`GHIDRA_INSTALL_DIR`, then Homebrew, then `PATH`. To point it at a specific
install:

```
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.x_PUBLIC scripts/run_headless.sh
```

Reports land in `reports/`, which is git-ignored.

## Running the binaries on macOS

The challenges are Linux ELF files. You can analyze them in Ghidra on any
OS, but to execute them on a Mac use a container:

```
docker run --rm -it --platform linux/amd64 -v "$PWD":/w -w /w gcc:14 bash
python3 solutions/run_tests.py bin
```

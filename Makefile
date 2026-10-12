# Builds the three training binaries as x86-64 Linux ELF files.
#
#   make            build into build/
#   make release    build, strip, and copy into bin/ (the committed binaries)
#   make test       run each binary against its solver
#   make docker     build inside a linux/amd64 container (for macOS hosts)
#   make clean

CC      ?= gcc
CFLAGS  ?= -O1 -fno-pie -no-pie -fno-stack-protector -Wall -Wextra
PYTHON  ?= python3
BUILD   := build

BINS := $(BUILD)/01-keygen $(BUILD)/02-hidden-strings $(BUILD)/03-tiny-vm

.PHONY: all release test docker clean

all: $(BINS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/enc_strings.h: tools/gen_strings.py | $(BUILD)
	$(PYTHON) tools/gen_strings.py $@

$(BUILD)/vm_code.h: tools/vm_asm.py | $(BUILD)
	$(PYTHON) tools/vm_asm.py $@

$(BUILD)/01-keygen: challenges/01-keygen/keygen.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/02-hidden-strings: challenges/02-hidden-strings/hidden.c $(BUILD)/enc_strings.h
	$(CC) $(CFLAGS) -I$(BUILD) -o $@ $<

$(BUILD)/03-tiny-vm: challenges/03-tiny-vm/vm.c $(BUILD)/vm_code.h
	$(CC) $(CFLAGS) -I$(BUILD) -o $@ $<

release: all
	mkdir -p bin
	for b in $(BINS); do strip -o bin/$$(basename $$b) $$b; done
	cd bin && sha256sum 0* > SHA256SUMS

test: all
	$(PYTHON) solutions/run_tests.py $(BUILD)

docker:
	docker run --rm --platform linux/amd64 -v "$(CURDIR)":/src -w /src gcc:14 \
		sh -c 'apt-get update -qq && apt-get install -y -qq python3 >/dev/null && make release test'

clean:
	rm -rf $(BUILD)

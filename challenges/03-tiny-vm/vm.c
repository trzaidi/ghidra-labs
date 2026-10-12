/*
 * Challenge 03: tiny VM
 *
 * Usage: ./03-tiny-vm <password>
 *
 * The password check does not live in native code. It runs as bytecode on
 * a small virtual machine embedded in the binary. Recover the VM state
 * structure and instruction set, disassemble the bytecode, and invert the
 * check to recover the password.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vm_code.h"

enum {
    OP_LDI = 0x10, OP_LDC = 0x11,
    OP_XOR = 0x20, OP_ADD = 0x21, OP_ROL = 0x22,
    OP_CMP = 0x30,
    OP_JNE = 0x40, OP_JMP = 0x41,
    OP_LEN = 0x50,
    OP_OK = 0xF0, OP_FAIL = 0xFF,
};

struct vm {
    uint8_t reg[4];
    uint8_t flag;
    uint16_t pc;
    uint16_t code_len;
    const uint8_t *code;
    const char *input;
    size_t input_len;
};

enum { VM_RUNNING, VM_ACCEPT, VM_REJECT, VM_FAULT };

static uint8_t rol8(uint8_t v, unsigned n)
{
    n &= 7;
    return (uint8_t)((v << n) | (v >> ((8 - n) & 7)));
}

__attribute__((noinline))
static int vm_load(struct vm *vm, const uint8_t *image, size_t size, const char *input)
{
    if (size < 6 || memcmp(image, "TVM1", 4) != 0)
        return 0;
    memset(vm, 0, sizeof(*vm));
    vm->code_len = (uint16_t)(image[4] | (image[5] << 8));
    if ((size_t)vm->code_len + 6 > size)
        return 0;
    vm->code = image + 6;
    vm->input = input;
    vm->input_len = strlen(input);
    return 1;
}

__attribute__((noinline))
static int vm_step(struct vm *vm)
{
    if (vm->pc >= vm->code_len)
        return VM_FAULT;

    const uint8_t *ip = vm->code + vm->pc;
    uint8_t a = (vm->pc + 1 < vm->code_len) ? ip[1] : 0;
    uint8_t b = (vm->pc + 2 < vm->code_len) ? ip[2] : 0;
    uint16_t addr = (uint16_t)(a | (b << 8));

    switch (ip[0]) {
    case OP_LDI:
        vm->reg[a & 3] = b;
        vm->pc += 3;
        break;
    case OP_LDC:
        vm->reg[a & 3] = (b < vm->input_len) ? (uint8_t)vm->input[b] : 0;
        vm->pc += 3;
        break;
    case OP_XOR:
        vm->reg[a & 3] ^= vm->reg[b & 3];
        vm->pc += 3;
        break;
    case OP_ADD:
        vm->reg[a & 3] += vm->reg[b & 3];
        vm->pc += 3;
        break;
    case OP_ROL:
        vm->reg[a & 3] = rol8(vm->reg[a & 3], b);
        vm->pc += 3;
        break;
    case OP_CMP:
        vm->flag = vm->reg[a & 3] == vm->reg[b & 3];
        vm->pc += 3;
        break;
    case OP_JNE:
        vm->pc = vm->flag ? (uint16_t)(vm->pc + 3) : addr;
        break;
    case OP_JMP:
        vm->pc = addr;
        break;
    case OP_LEN:
        vm->reg[a & 3] = (uint8_t)vm->input_len;
        vm->pc += 2;
        break;
    case OP_OK:
        return VM_ACCEPT;
    case OP_FAIL:
        return VM_REJECT;
    default:
        return VM_FAULT;
    }
    return VM_RUNNING;
}

int main(int argc, char **argv)
{
    struct vm vm;
    int state = VM_RUNNING;
    unsigned steps = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <password>\n", argv[0]);
        return 2;
    }
    if (!vm_load(&vm, VM_IMAGE, sizeof(VM_IMAGE), argv[1])) {
        fputs("corrupt VM image\n", stderr);
        return 3;
    }
    while (state == VM_RUNNING && steps++ < 10000)
        state = vm_step(&vm);

    if (state == VM_ACCEPT) {
        printf("Correct! Flag: GT{%s}\n", argv[1]);
        return 0;
    }
    puts("Wrong password.");
    return 1;
}

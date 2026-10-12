/*
 * Challenge 01: keygen
 *
 * Usage: ./01-keygen <name> <serial>
 *
 * The serial is derived from the name. Recover the algorithm in Ghidra
 * and write a key generator that produces a valid serial for any name.
 */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_MIN 4
#define NAME_MAX 32

static uint32_t rol32(uint32_t v, unsigned n)
{
    return (v << n) | (v >> (32 - n));
}

__attribute__((noinline))
static uint32_t name_hash(const char *name)
{
    uint32_t h = 0x1337C0DEu;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h ^= (uint32_t)toupper(*p);
        h = rol32(h, 5);
        h *= 0x01000193u;
    }
    return h;
}

__attribute__((noinline))
static uint16_t name_checksum(const char *name)
{
    uint32_t sum = 0;
    size_t len = strlen(name);
    for (size_t i = 0; i < len; i++)
        sum += (uint32_t)(unsigned char)name[i] * (uint32_t)(i + 1);
    return (uint16_t)(sum * (uint32_t)len);
}

__attribute__((noinline))
static int parse_serial(const char *s, uint16_t out[4])
{
    if (strlen(s) != 19)
        return 0;
    for (int g = 0; g < 4; g++) {
        uint16_t v = 0;
        for (int i = 0; i < 4; i++) {
            char c = s[g * 5 + i];
            int d;
            if (c >= '0' && c <= '9')
                d = c - '0';
            else if (c >= 'A' && c <= 'F')
                d = c - 'A' + 10;
            else
                return 0;
            v = (uint16_t)((v << 4) | d);
        }
        out[g] = v;
        if (g < 3 && s[g * 5 + 4] != '-')
            return 0;
    }
    return 1;
}

__attribute__((noinline))
static int check_serial(const char *name, const char *serial)
{
    size_t len = strlen(name);
    uint16_t parts[4];

    if (len < NAME_MIN || len > NAME_MAX)
        return 0;
    if (!parse_serial(serial, parts))
        return 0;

    uint32_t h = name_hash(name);
    uint16_t a = (uint16_t)(h >> 16);
    uint16_t b = (uint16_t)(h & 0xFFFF);
    uint16_t c = (uint16_t)(a ^ b ^ 0xBEEF);
    uint16_t d = name_checksum(name);

    return parts[0] == a && parts[1] == b && parts[2] == c && parts[3] == d;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <name> <serial>\n", argv[0]);
        return 2;
    }
    if (check_serial(argv[1], argv[2])) {
        puts("Serial accepted. Welcome, licensed user.");
        return 0;
    }
    puts("Invalid serial.");
    return 1;
}

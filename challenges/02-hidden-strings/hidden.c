/*
 * Challenge 02: hidden strings
 *
 * Usage: ./02-hidden-strings
 *
 * Running `strings` on this binary will not show you the access code or
 * the flag. Find how the program hides its strings, then recover all of
 * them statically, without running the binary.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "enc_strings.h"

/* A decoy. Plaintext strings in a binary are not always what they seem. */
const char *debug_banner = "debug_password=hunter2";

__attribute__((noinline))
static void decrypt(char *dst, const uint8_t *src, size_t len, uint8_t key)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = (char)(src[i] ^ (uint8_t)(key + i * 0x1F));
    dst[len] = '\0';
}

int main(void)
{
    char buf[64];
    char input[64];
    char expected[64];

    decrypt(buf, ENC_PROMPT, sizeof(ENC_PROMPT), KEY_PROMPT);
    fputs(buf, stdout);
    fflush(stdout);

    if (!fgets(input, sizeof(input), stdin))
        return 1;
    input[strcspn(input, "\r\n")] = '\0';

    decrypt(expected, ENC_PASSWORD, sizeof(ENC_PASSWORD), KEY_PASSWORD);
    if (strcmp(input, expected) == 0) {
        decrypt(buf, ENC_GRANTED, sizeof(ENC_GRANTED), KEY_GRANTED);
        fputs(buf, stdout);
        decrypt(buf, ENC_FLAG, sizeof(ENC_FLAG), KEY_FLAG);
        puts(buf);
        return 0;
    }

    decrypt(buf, ENC_DENIED, sizeof(ENC_DENIED), KEY_DENIED);
    puts(buf);
    return 1;
}

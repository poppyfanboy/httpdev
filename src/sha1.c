#include <string.h> // memset

#include "common.h"

u32 u32_rotate_left(u32 value, int amount) {
    return value << amount | value >> (32 - amount);
}

// The first 16 elements must contain the input 512 bit block.
void sha1_process_block(u32 words[80], u32 h[5]) {
    for (isize t = 16; t < 80; t += 1) {
        u32 word = words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16];
        word = u32_rotate_left(word, 1);
        words[t] = word;
    }

    u32 a = h[0];
    u32 b = h[1];
    u32 c = h[2];
    u32 d = h[3];
    u32 e = h[4];

    for (int t = 0; t < 20; t += 1) {
        u32 f = b & c | ~b & d;
        u32 k = 0x5a827999;
        u32 temp = u32_rotate_left(a, 5) + f + e + words[t] + k;
        e = d;
        d = c;
        c = u32_rotate_left(b, 30);
        b = a;
        a = temp;
    }

    for (int t = 20; t < 40; t += 1) {
        u32 f = b ^ c ^ d;
        u32 k = 0x6ed9eba1;
        u32 temp = u32_rotate_left(a, 5) + f + e + words[t] + k;
        e = d;
        d = c;
        c = u32_rotate_left(b, 30);
        b = a;
        a = temp;
    }

    for (int t = 40; t < 60; t += 1) {
        u32 f = b & c | b & d | c & d;
        u32 k = 0x8f1bbcdc;
        u32 temp = u32_rotate_left(a, 5) + f + e + words[t] + k;
        e = d;
        d = c;
        c = u32_rotate_left(b, 30);
        b = a;
        a = temp;
    }

    for (int t = 60; t < 80; t += 1) {
        u32 f = b ^ c ^ d;
        u32 k = 0xca62c1d6;
        u32 temp = u32_rotate_left(a, 5) + f + e + words[t] + k;
        e = d;
        d = c;
        c = u32_rotate_left(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// https://en.wikipedia.org/wiki/SHA-1
// https://www.rfc-editor.org/rfc/rfc3174
void sha1(u8 const *input, isize input_size, u32 hash[5]) {
    u8 const *input_iter = input;
    u8 const *input_end = input + input_size;

    hash[0] = 0x67452301;
    hash[1] = 0xefcdab89;
    hash[2] = 0x98badcfe;
    hash[3] = 0x10325476;
    hash[4] = 0xc3d2e1f0;

    // Fist process all full 512-bit blocks from the input:
    while (input_end - input_iter >= 64) {
        u32 input_words[80];
        for (isize t = 0; t < 16; t += 1) {
            input_words[t] =
                (u32)input_iter[0] << 24 |
                (u32)input_iter[1] << 16 |
                (u32)input_iter[2] <<  8 |
                (u32)input_iter[3];
            input_iter += 4;
        }
        sha1_process_block(input_words, hash);
    }

    u32 tail[80] = {0};
    u32 *tail_iter = tail;
    u32 *tail_end = tail + 16;

    while (input_end - input_iter >= 4) {
        *tail_iter =
            (u32)input_iter[0] << 24 |
            (u32)input_iter[1] << 16 |
            (u32)input_iter[2] <<  8 |
            (u32)input_iter[3];

        tail_iter += 1;
        input_iter += 4;
    }

    *tail_iter |= (u32)0x80 << ((3 - (input_end - input_iter)) * 8);

    if (input_iter < input_end) {
        *tail_iter |= (u32)*input_iter << 24;
        input_iter += 1;
    }
    if (input_iter < input_end) {
        *tail_iter |= (u32)*input_iter << 16;
        input_iter += 1;
    }
    if (input_iter < input_end) {
        *tail_iter |= (u32)*input_iter << 8;
        input_iter += 1;
    }

    tail_iter += 1;

    // We can't fit the message size into the current block, put it into the next one.
    if (tail_end - tail_iter < 2) {
        sha1_process_block(tail, hash);
        memset(tail, 0, sizeof(tail));
    }

    u64 bit_size = input_size * 8;
    tail_end[-2] = bit_size >> 32;
    tail_end[-1] = bit_size & 0xffffffff;

    sha1_process_block(tail, hash);
}

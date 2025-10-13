#include "common.h"

char to_base64_char[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

isize base64_encode(
    u8 const *input, isize input_size,
    char *output_buffer
) {
    if (output_buffer == NULL) {
        // Compute the padded size of the output string.
        return (input_size + 2) / 3 * 4;
    }

    u8 const *input_iter = input;
    u8 const *input_end = input + input_size;

    char *output_iter = output_buffer;

    while (input_end - input_iter >= 3) {
        *(output_iter++) = to_base64_char[input_iter[0] >> 2];
        *(output_iter++) = to_base64_char[(input_iter[0] & 0x03) << 4 | (input_iter[1] >> 4)];
        *(output_iter++) = to_base64_char[(input_iter[1] & 0x0f) << 2 | (input_iter[2] >> 6)];
        *(output_iter++) = to_base64_char[input_iter[2] & 0x3f];

        input_iter += 3;
    }

    if (input_end - input_iter == 2) {
        *(output_iter++) = to_base64_char[input_iter[0] >> 2];
        *(output_iter++) = to_base64_char[(input_iter[0] & 0x03) << 4 | (input_iter[1] >> 4)];
        *(output_iter++) = to_base64_char[(input_iter[1] & 0x0f) << 2];
        *(output_iter++) = '=';
    }

    if (input_end - input_iter == 1) {
        *(output_iter++) = to_base64_char[input_iter[0] >> 2];
        *(output_iter++) = to_base64_char[(input_iter[0] & 0x03) << 4];
        *(output_iter++) = '=';
        *(output_iter++) = '=';
    }

    return output_iter - output_buffer;
}

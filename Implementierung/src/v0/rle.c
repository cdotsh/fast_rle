#include "rle.h"
#include "../pbm.h"
#include "../helpers/bit_ops_helpers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>



// maybe idea for simd? https://stackoverflow.com/questions/55439622/get-index-of-first-element-that-is-not-zero-in-a-m256-variable/55439918#55439918

size_t run_length_encode_max_length(size_t width, size_t height) {
    // if input is a stream of alternating pixels
    // pixel_buf_size because we also encode the padding bits at the end of each row
    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);
    size_t bits_to_encode = pixel_buf_size * 8;
    size_t max_rle_bit_size =  bits_to_encode * (LENGTH_BIT_SIZE + 1);
    if (max_rle_bit_size / bits_to_encode != (LENGTH_BIT_SIZE + 1)) {
        printf("computing the max rle buffer length overflowed\n");
        exit(-1);
    }
    return max_rle_bit_size / 8 + (max_rle_bit_size % 8 != 0);
}

// this function assumes that rle_data is 0 initialized
size_t run_length_encode(const uint8_t* img, size_t width, size_t height, uint8_t* rle_data) {
    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);

    bool current_color = (img[0] >> 7) & 1;
    size_t current_count = 0;

    size_t rle_bit_idx = 0;
    for (size_t byte_idx = 0; byte_idx < pixel_buf_size; byte_idx++) {
        uint8_t read_byte = img[byte_idx];

        // check if the byte only contains ones or zeroes
        // (current_count + 8) < pow(2, LENGTH_BIT_SIZE) - 1
        if ((current_count + 8) < ((size_t)1 << LENGTH_BIT_SIZE) - 1 &&
             ((read_byte == 0xff && current_color == 1) || (read_byte == 0x0 && current_color == 0))) {
            current_count += 8;
        } else {
            // we are encoding the filler bits at the end of each row here aswell, but that
            // 1) shouldn't really make a difference on the average image
            // 2) makes things easier to implement
            for (size_t i=0; i<8; i++) {
                bool pixel_value = (read_byte >> (7 - i)) & 1;
                if (pixel_value != current_color
                    || current_count == ((size_t)1 << LENGTH_BIT_SIZE) - 1) { // == max length we can store with LENGTH_BIT_SIZE bits
                    //printf("encoding: %d %lu at %lu\n", current_color, current_count, rle_bit_idx);
                    write_bit(rle_data, rle_bit_idx, current_color);
                    rle_bit_idx += 1;
                    encode_n_bit_num(rle_data, rle_bit_idx, current_count, LENGTH_BIT_SIZE);
                    rle_bit_idx += LENGTH_BIT_SIZE;
                    current_color = pixel_value;
                    current_count = 1;
                } else {
                    current_count += 1;
                }
            }
        }
    }
    //printf("encoding: %d %lu at %lu\n", current_color, current_count, rle_bit_idx);
    write_bit(rle_data, rle_bit_idx, current_color);
    rle_bit_idx += 1;
    encode_n_bit_num(rle_data, rle_bit_idx, current_count, LENGTH_BIT_SIZE);
    rle_bit_idx += LENGTH_BIT_SIZE;
    return (rle_bit_idx / 8) + (rle_bit_idx % 8 > 0);
}

void run_length_decode(const uint8_t* rle_data, size_t len, size_t width, size_t height, uint8_t* img) {
    // points to next unread bit index
    size_t rle_bit_idx = 0;
    size_t rle_bit_len_total = len * 8;
    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);
    size_t expected_bit_amount = pixel_buf_size * 8;

    if (expected_bit_amount / 8 != pixel_buf_size
        || rle_bit_len_total / 8 != len) {
        printf("overflow detected in decoding\n");
        exit(-1);
    }

    size_t bits_written = 0;

    while (rle_bit_idx + LENGTH_BIT_SIZE + 1 <= rle_bit_len_total && bits_written < expected_bit_amount) {
        bool color = read_bit(rle_data, rle_bit_idx);
        rle_bit_idx += 1;
        size_t amount = decode_n_bit_num(rle_data, rle_bit_idx, LENGTH_BIT_SIZE);
        rle_bit_idx += LENGTH_BIT_SIZE;
        //printf("decoded: %d %lu at %lu len:%lu\n", color, amount, rle_bit_idx - LENGTH_BIT_SIZE - 1, len);
        if (bits_written + amount > expected_bit_amount) {
            printf("More bits encoded than indicated by dimensions\n");
            exit(-1);
        }

        set_n_bits(amount, img, bits_written, color);

        bits_written += amount;
    }

    if (bits_written != expected_bit_amount) {
        printf("decoded bit amount != expected bit amount\n");
        exit(-1);
    }
}

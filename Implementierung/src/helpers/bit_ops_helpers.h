#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

void write_bit(uint8_t *write_buf, size_t bit_offset, bool bit_val);
bool read_bit(const uint8_t *read_buf, size_t bit_offset);

void encode_n_bit_num(uint8_t *out_buf, size_t bit_offset, size_t num, size_t bit_size);
size_t decode_n_bit_num(const uint8_t *in_buf, size_t bit_offset, size_t bit_size);

// helper method to set n bits in a buffer from a bit offset (pretty much used exclusively for setting pixels in a pbm buf)
// assumes that out_buf is 0 initialized
void set_n_bits(size_t amount, uint8_t *out_buf, size_t start_bit_idx, bool bit_val);
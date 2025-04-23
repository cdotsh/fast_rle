#include "bit_ops_helpers.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

// https://stackoverflow.com/questions/47981/how-do-i-set-clear-and-toggle-a-single-bit/47990#47990
void write_bit(uint8_t *write_buf, size_t bit_offset, bool bit_val) {
    write_buf[bit_offset / 8] ^= (-bit_val ^ write_buf[bit_offset / 8]) & (1UL << (7 - (bit_offset % 8)));
}

bool read_bit(const uint8_t *read_buf, size_t bit_offset) {
    return (read_buf[bit_offset / 8] >> (7 - (bit_offset % 8))) & 1U;
}

void encode_n_bit_num(uint8_t *out_buf, size_t bit_offset, size_t num, size_t bit_size) {
    #ifndef NDEBUG
    size_t expected_idx = bit_offset + bit_size;
    #endif // NDEBUG
    // fill remaining bits until we're byte aligned
    size_t until_byte_aligned = (8 - (bit_offset % 8)) % 8;
    size_t init_write_amount = bit_size > until_byte_aligned ? until_byte_aligned : bit_size;
    if (init_write_amount > 0) {
        // init_write_amount top bits set to 1
        size_t select_mask = ((1 << init_write_amount) - 1);
        // set to 0 first
        out_buf[bit_offset / 8] &= ~(select_mask << (until_byte_aligned - init_write_amount));
        // now we can just or
        out_buf[bit_offset / 8] |= ((num >> (bit_size - init_write_amount)) & select_mask) << (until_byte_aligned - init_write_amount);
        bit_offset += init_write_amount;
    }

    // now we can just copy byte-by-byte
    // should be guaranteed not to underflow by the way init_write_amount as chosen
    size_t remaining = bit_size - init_write_amount;
    assert(remaining <= bit_size);
    // remaining / 8 > 0
    while (remaining >> 3 > 0) {
        size_t select_mask = ((size_t)0xff << (remaining - 8));
        out_buf[bit_offset / 8] = (num & select_mask) >> (remaining - 8);
        bit_offset +=  8;
        remaining -= 8;
    }
    // fill the last byte
    if (remaining) {
        size_t select_mask = ((1 << remaining) - 1);
        out_buf[bit_offset / 8] &= ~(select_mask << (8 - remaining % 8));
        out_buf[bit_offset / 8] |= (num & select_mask) << (8 - remaining % 8);
        bit_offset += remaining;
    }
    assert(expected_idx == bit_offset);
}

size_t decode_n_bit_num(const uint8_t *in_buf, size_t bit_offset, size_t bit_size) {
    size_t until_byte_aligned = (8 - bit_offset % 8) % 8;
    size_t init_read_amount = bit_size > until_byte_aligned ? until_byte_aligned : bit_size;
    size_t select_mask = ((1 << init_read_amount) - 1);
    size_t read_num = (in_buf[bit_offset / 8]  >> (until_byte_aligned - init_read_amount)) & select_mask;
    bit_offset += init_read_amount;

    // now we can just read byte-by-byte

    // should be guaranteed not to underflow by the way init_read_amount as chosen
    size_t remaining = bit_size - init_read_amount;
    assert(remaining <= bit_size);
    // remaining / 8 > 0
    while (remaining >> 3 > 0) {
        read_num <<= 8;
        read_num |= in_buf[bit_offset >> 3];
        bit_offset += 8;
        remaining -= 8;
    }

    // read last byte
    if (remaining) {
        read_num <<= remaining;
        read_num |= in_buf[bit_offset >> 3] >> (8 - remaining); // no modulo needed here since remaining is guaranteed non-zero
        bit_offset += remaining;
    }
    return read_num;
}

// pretty much just sets the next amount pixels in the image to the provided value
void set_n_bits(size_t amount, uint8_t *out_buf, size_t start_bit_idx, bool bit_val) {
    size_t target_bit_idx = start_bit_idx + amount;

    size_t size_to_write = amount;

    //size_t current_byte_idx = bytes_width * (start_bit_idx / width) + ((start_bit_idx % width) / 8);
    size_t curr_bit_idx = start_bit_idx;
    size_t until_byte_aligned = (8 - (start_bit_idx % 8)) % 8;
    size_t init_write_amount = size_to_write > until_byte_aligned ? until_byte_aligned : size_to_write;
    if (init_write_amount) {
        size_t new_bits = ((1 << init_write_amount) - 1) << (until_byte_aligned - init_write_amount);
        if (bit_val) {
            out_buf[curr_bit_idx >> 3] |= new_bits;
        } else {
            out_buf[curr_bit_idx >> 3] &= ~new_bits;
        }
        curr_bit_idx += init_write_amount;
    }
    assert(curr_bit_idx % 8 == 0 || curr_bit_idx == target_bit_idx);

    while ((target_bit_idx - curr_bit_idx) >= 8) {
        out_buf[curr_bit_idx >> 3] = bit_val ? 0xff : 0;
        curr_bit_idx += 8;
    }

    if (target_bit_idx > curr_bit_idx) {
        size_t remaining = target_bit_idx - curr_bit_idx;
        assert(remaining < 8);
        size_t new_bits = ((1 << remaining) - 1) << (8 - remaining);
        if (bit_val) {
            out_buf[curr_bit_idx >> 3] |= new_bits;
        } else {
            out_buf[curr_bit_idx >> 3] &= ~new_bits;
        }
        curr_bit_idx += remaining;
    }
    assert(curr_bit_idx == target_bit_idx);
}
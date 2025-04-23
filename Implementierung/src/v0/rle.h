#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// has to be 1 < x < 64
static size_t LENGTH_BIT_SIZE = 7;

size_t run_length_encode_max_length(size_t width, size_t height);

// wrapper functions
size_t run_length_encode(const uint8_t* img, size_t width, size_t height, uint8_t* rle_data);
void run_length_decode(const uint8_t* rle_data, size_t len, size_t width, size_t height, uint8_t* img);

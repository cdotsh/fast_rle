#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct encode_thread_params {
    size_t thread_id;
    size_t pixel_buf_size;      // number of bytes to be read from this thread
    const uint8_t *img;
    uint8_t *rle_data;          // output array
    size_t bytes_written;        // return value
} encode_thread_params;

typedef struct decode_thread_params {
    size_t thread_id;
    const uint8_t *rle_data;          // input array
    size_t rle_len;         // number of bytes to be read from this thread
    uint8_t *img;
    size_t max_bits;        // max number of decoded bits to be expected
    size_t bits_written;
} decode_thread_params;

size_t run_length_encode_v1(const uint8_t* img, size_t width, size_t height, uint8_t* rle_data);
void run_length_decode_v1(const uint8_t* rle_data, size_t len, size_t width, size_t height, uint8_t* img);
#include "rle_v1.h"
#include "../helpers/bit_ops_helpers.h"
#include "../helpers/safe_malloc.h"
#include "../pbm.h"
#include "../v0/rle.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#define N_THREADS 4

#define calc_thread_split_size(n_threads, pixel_buf_size) pixel_buf_size / n_threads + (pixel_buf_size % n_threads > 0)

void* run_length_encode_thread(encode_thread_params *encoding_params) {
    encoding_params->bytes_written = run_length_encode(encoding_params->img, 
        encoding_params->pixel_buf_size * 8, 1, encoding_params->rle_data);
    pthread_exit(0);
}


size_t *partition_for_threads(size_t total_bit_amount) {
    size_t *result_arr = (size_t *)safe_malloc(sizeof(size_t) * N_THREADS);
    size_t bits_per_thread = total_bit_amount / N_THREADS;
    for (size_t thread_id = 0; thread_id<N_THREADS - 1; thread_id++) {
        result_arr[thread_id] = bits_per_thread;
    }
    result_arr[N_THREADS - 1] = bits_per_thread + total_bit_amount % N_THREADS;
    return result_arr;
}

// expects LENGTH_BIT_SIZE to be 7
size_t run_length_encode_v1(const uint8_t* img, size_t width, size_t height, uint8_t* rle_data){
    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);  // number of bytes to be compressed
    size_t n_threads = pixel_buf_size < N_THREADS ? pixel_buf_size : N_THREADS;

    size_t thread_bytes_amount = pixel_buf_size / n_threads; // number of bytes to be compressed for each thread (except the last one)
    pthread_t threads[n_threads];
    encode_thread_params encode_params[n_threads];                     // arguments for the thread encode function
    size_t output_size = 0;

    for (size_t i = 0; i < n_threads; i++) {
        size_t pixel_buf_bytes = thread_bytes_amount + (i == n_threads - 1) * pixel_buf_size % n_threads;

        size_t pixel_buf_bits = pixel_buf_bytes * 8;
        if (pixel_buf_bits >> 3 != pixel_buf_bytes) {
            printf("calculating pixel_buf_bits overflowed");
            exit(-1);
        }
        size_t max_rle_size = run_length_encode_max_length(1, pixel_buf_bits);
        encode_params[i].thread_id = i;
        encode_params[i].pixel_buf_size = thread_bytes_amount + (i == n_threads - 1) * pixel_buf_size % n_threads;
        encode_params[i].img = &img[thread_bytes_amount * i];
        encode_params[i].rle_data = (uint8_t *)safe_malloc(max_rle_size);

        pthread_create(&(threads[i]), NULL, (void * (*)(void *))run_length_encode_thread, (void *) &encode_params[i]);
    }

    for (size_t i = 0; i < n_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    for (size_t i = 0; i < n_threads; i++) {
        output_size += encode_params[i].bytes_written;
    }

    // combine encoded data into one array
    size_t index = 0;
    for (size_t i = 0; i < n_threads; i++) {
        for (size_t k = 0; k < encode_params[i].bytes_written; k++) {
            rle_data[index++] = encode_params[i].rle_data[k];
        }
    }

    for (size_t i = 0; i < n_threads; i++) {
        free(encode_params[i].rle_data); 
    }

    return output_size;
}

void* run_length_decode_thread(decode_thread_params *decode_params) {
    // points to next unread bit index
    size_t rle_bit_idx = 0;
    size_t rle_total_bits_len = decode_params->rle_len * 8;

    if (rle_total_bits_len / 8 != decode_params->rle_len) {
        printf("computing rle_total_bits_len overflowed\n");
        exit(-1);
    }

    size_t bits_written = 0;
    while (rle_bit_idx + LENGTH_BIT_SIZE + 1 <= rle_total_bits_len) {
        bool color =read_bit(decode_params->rle_data, rle_bit_idx);
        rle_bit_idx += 1;
        size_t amount = decode_n_bit_num(decode_params->rle_data, rle_bit_idx, LENGTH_BIT_SIZE);
        rle_bit_idx += LENGTH_BIT_SIZE;
        //printf("decoded: %d %lu at %lu len:%lu\n", color, amount, rle_bit_idx - LENGTH_BIT_SIZE - 1, decode_params->rle_len);

        set_n_bits(amount, decode_params->img, bits_written, color);

        bits_written += amount;
    }

    decode_params->bits_written = bits_written;
    pthread_exit(0);
}

// expects LENGTH_BIT_SIZE to be 7
void run_length_decode_v1(const uint8_t* rle_data, size_t len, size_t width, size_t height, uint8_t* img){
    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);  // number of bytes to be compressed

    size_t n_threads = pixel_buf_size < N_THREADS ? pixel_buf_size : N_THREADS;

    size_t split_size = calc_thread_split_size(n_threads, pixel_buf_size); // number of bytes to be compressed for each thread
    pthread_t threads[n_threads];
    decode_thread_params decode_params[n_threads];                     // arguments for the thread encode function

    for (size_t i = 0; i < n_threads; i++) {
        decode_params[i].thread_id = i;
        decode_params[i].rle_len = len / n_threads;
        if(i == n_threads-1) {
            decode_params[i].rle_len = len / n_threads + len % n_threads; // last thread decodes the rest
        }

        decode_params[i].max_bits = split_size;  // max value
        decode_params[i].img = (uint8_t *)safe_malloc(pixel_buf_size);         // TODO: approximate worst case buffer size better 
        decode_params[i].rle_data = rle_data + (len / n_threads) * i;      // image data + offset
        pthread_create(&(threads[i]), NULL, (void * (*)(void *))run_length_decode_thread, (void *) &decode_params[i]);
    }

    for (size_t i = 0; i < n_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    size_t total_bits_expected = pixel_buf_size * 8;
    if (total_bits_expected / 8 != pixel_buf_size) {
        printf("computing total_bits_expected overflowed\n");
        exit(-1);
    }

    // move decoded bits into one array
    size_t final_img_bit_idx = 0;
    for (size_t i = 0; i < n_threads; i++) {
        size_t bits_to_copy = decode_params[i].bits_written;
        size_t thread_img_bit_idx = 0;
        for (size_t copy_idx = 0; copy_idx<decode_params[i].bits_written; copy_idx++) {
            if (final_img_bit_idx  >= total_bits_expected) {
                printf("encoded bits don't match dimensions\n");
                exit(-1);
            }
            write_bit(img, final_img_bit_idx, read_bit(decode_params[i].img, copy_idx));
            final_img_bit_idx += 1;
        }
    }

    if (final_img_bit_idx != total_bits_expected) {
        printf("encoded pixel amount doesn't match dimensions");
        exit(-1);
    }

    // free buffers
    for (size_t i = 0; i < n_threads; i++) {
        free(decode_params[i].img);
    }
}

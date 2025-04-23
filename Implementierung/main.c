#include "src/pbm.h"
#include "src/v0/rle.h"
#include "src/v1/rle_v1.h"
#include "src/v2/huffman.h"
#include "src/compressed_format.h"
#include "src/helpers/safe_malloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define RESET "\x1B[0m"
#define BOLD "\x1B[1m"

void print_help() {
    printf("%sUSAGE:%s\n", BOLD, RESET);
    printf("./main [OPTIONS] [INPUT FILE]\n");
    printf("\n%sOPTIONS:%s\n", BOLD, RESET);
    printf("\t-V [version number]\t\tSpecifies the version for encoding/decoding (0-2). -V0 by default.\n");
    printf("\t-B [repetitions (optional)]\tPerforms runtime measurements when set. Optionally defines the number of repetitions.\n");
    printf("\t-o <Path to File>\t\tSpecifies the output file.\n");
    printf("\n%sExamples:%s\n", BOLD, RESET);
    printf("\tEncode: ./main -V0 image.pbm\n");
    printf("\tDecode: ./main -V0 -d compressed.bin\n\n");
}

int main(int argc, char **argv) {
    //int v                     = used implementation (default = 0)
    //int b                     = number of repetitions if execution time is measured
    //bool measure_time         = true if time measurement will be executed
    //bool decode               = true -> decode; false -> encode
    //char* output_file         = file name of output
    //char* input_file          = file name of input
    static struct option long_opt[] = {{"help", no_argument, NULL, 'h'}};
    int opt, v = 0, iteration_amount = 0;
    bool measure_time = false, decode = false;
    char* output_file = NULL, *input_file;
    while ((opt = getopt_long(argc, argv, "V:B::do:h", long_opt, NULL)) != -1) {
        switch (opt) {
            case 'V':
                if(!isdigit(optarg[0])) {
                    fprintf(stderr, "The option 'V' requires a version numbers. See --help for more information.\n");
                    exit(EXIT_FAILURE);
                }
                v = (int)atol(optarg);
                break;
            case 'B':
                measure_time = true;
                iteration_amount = 1;
                if(optarg) {
                    iteration_amount = (int)atol(optarg);
                    if(iteration_amount < 1) {
                        fprintf(stderr, "The number of repetitions has to be an positive number.\n");
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            case 'd':
                decode = true;
                break;
            case 'o':
                if(!optarg) {
                    fprintf(stderr, "The option 'o' needs an argument. See --help for more information.\n");
                    exit(EXIT_FAILURE);
                }
                output_file = optarg;
                break;
            default:
                fprintf(stderr, "The option is undefined. See --help for more information.\n");
                exit(EXIT_FAILURE);
        }
    }
    if((optind != argc - 1)) {
        fprintf(stderr, "The wrong number of arguments was passed. See --help for more information\n");
        exit(EXIT_FAILURE);
    }
    input_file = argv[optind];

    if (decode) {
        if (!output_file) {
            output_file = "decoded.pbm";
        }

        compressed_data parse_res;
        switch (compressed_parse(input_file, &parse_res)) {
            case 0: break; // worked
            case -1:  printf("failed to open file\n"); exit(-1);
            default: printf("file has invalid format\n"); exit(-1);
        }

        size_t pixel_buf_size = pbm_pixel_buf_size(parse_res.width, parse_res.height);
        uint8_t *result = safe_malloc(pixel_buf_size);

        void (*decoding_func)(const uint8_t*, size_t, size_t, size_t, uint8_t*);

        switch (v) {
            case 0: {
                decoding_func = run_length_decode;
                break;
            }
            case 1: {
                decoding_func = run_length_decode_v1;
                break;
            }
            case 2: {
                decoding_func = run_length_decode_huffman;
                break;
            }
            default: {
                printf("version not implemented\n");
                exit(-1);
            }
        }

        if(!measure_time) {
            decoding_func(parse_res.encoded_part, parse_res.encoded_part_size, parse_res.width, parse_res.height, result);
        } else {
            struct timespec start;
            clock_gettime(CLOCK_MONOTONIC , &start) ;
            for (int i=0; i<iteration_amount; i++) {
                // Maybe also measure the buffer allocation of result?
                decoding_func(parse_res.encoded_part, parse_res.encoded_part_size, parse_res.width, parse_res.height, result);
            }
            struct timespec end;
            clock_gettime(CLOCK_MONOTONIC, &end);
            double time = end.tv_sec - start.tv_sec + 1e-9 * (end.tv_nsec - start.tv_nsec);
            double avg_time = time / iteration_amount;

            printf("Total time: %lf\n", time);
            printf("Average Time: %lf\n", avg_time);
        }

        // write data to output file
        if (pbm_dump(output_file, parse_res.width, parse_res.height, result) != 0) {
                printf("saving decoded image failed\n");
                exit(-1);
        }
    } else { // encode

        if (!output_file) {
            output_file = "compressed.bin";
        }

        PBM_Image result_struct; 

        switch (pbm_parse(input_file, &result_struct)) {
            case 0: break; // worked
            case -1:  printf("failed to open file\n"); exit(-1);
            default: printf("file has invalid format\n"); exit(-1);
        }

        uint8_t *rle_data;
        int enc_val = 0;

        size_t (*encoding_func)(const uint8_t* , size_t, size_t, uint8_t*);
        size_t (*max_buf_len_func)(size_t, size_t);

        switch (v) {
            case 0: {
                max_buf_len_func = run_length_encode_max_length;
                encoding_func = run_length_encode;
                break;
            }
            case 1: {
                max_buf_len_func = run_length_encode_max_length;
                encoding_func = run_length_encode_v1;
                break;
            }
            case 2: {
                max_buf_len_func = rle_huffman_max_length;
                encoding_func = run_length_encode_huffman;
                break;
            }
            default: {
                printf("version not implemented\n");
                exit(-1);
            }
        }

        rle_data = safe_malloc(max_buf_len_func(result_struct.width, result_struct.height));
        if (!measure_time) {
            enc_val = encoding_func(result_struct.pixel_vals, result_struct.width, result_struct.height, rle_data);

        } else { // benchmarking enabled
            struct timespec start;
            clock_gettime(CLOCK_MONOTONIC , &start) ;
            for (int i=0; i<iteration_amount; i++) {
                enc_val = encoding_func(result_struct.pixel_vals, result_struct.width, result_struct.height, rle_data);
            }
            struct timespec end;
            clock_gettime(CLOCK_MONOTONIC, &end);

            double time = end.tv_sec - start.tv_sec + 1e-9 * (end.tv_nsec - start.tv_nsec);
            double avg_time = time / iteration_amount;

            printf("Total time: %lf\n", time);
            printf("Average Time: %lf\n", avg_time);
        }

        // write data to output file
        if(compressed_dump(output_file, result_struct.width, result_struct.height, rle_data, enc_val) != 0){
                printf("Couldn't dump compressed data into file.\n");
                exit(-1);
        }
        free(rle_data);
    }
    exit(EXIT_SUCCESS);
}

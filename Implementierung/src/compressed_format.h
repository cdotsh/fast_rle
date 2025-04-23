#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct compressed_data {
    size_t width;
    size_t height;
    uint8_t *encoded_part;
    size_t encoded_part_size;
} compressed_data;

// pretty much just provides a reusable way to open a file and read the size + height and provide a pointer to the
// part of the file that is encoded with a specific implementation

// return value is non 0 if anything failed
int compressed_parse(char *file_name, compressed_data *result_struct);
int compressed_dump(char *file_name, size_t width, size_t height, uint8_t *encoded_part, size_t encoded_part_size);
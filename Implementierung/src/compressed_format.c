#include "compressed_format.h"
#include "helpers/safe_malloc.h"

#include <stdint.h>
#include <stdio.h>

int compressed_parse(char *file_name, compressed_data *result_struct) {
    FILE *stream = fopen(file_name, "r");
    if (!stream) {
        return -1;
    }

    if (!fread(&result_struct->width, sizeof(typeof(result_struct->width)) , 1, stream)) {
        return -2;
    }

    if (!fread(&result_struct->height, sizeof(typeof(result_struct->height)), 1, stream)) {
        return -3;
    }

    //sanity check
    if (result_struct->height == 0) {
        return -8;
    }
    if (result_struct->width == 0) {
        return -9;
    }

    if (!fread(&result_struct->encoded_part_size, sizeof(typeof(result_struct->encoded_part_size)), 1, stream)) {
        return -4;
    }

    result_struct->encoded_part = safe_malloc(result_struct->encoded_part_size);
    if (fread(result_struct->encoded_part, 1, result_struct->encoded_part_size, stream) != result_struct->encoded_part_size) {
        return -5;
    }

    fclose(stream);

    return 0;
}

int compressed_dump(char *file_name, size_t width, size_t height, uint8_t *encoded_part, size_t encoded_part_size) {
    FILE *stream = fopen(file_name, "w");
    if (!stream) {
        return -1;
    }

    if (!fwrite(&width, sizeof(typeof(width)) , 1, stream)) {
        return -2;
    }

    if (!fwrite(&height, sizeof(typeof(height)), 1, stream)) {
        return -3;
    }

    if (!fwrite(&encoded_part_size, sizeof(typeof(encoded_part_size)), 1, stream)) {
        return -4;
    }

    if (fwrite(encoded_part, 1, encoded_part_size, stream) != encoded_part_size) {
        return -5;
    }

    fclose(stream);

    return 0;
}
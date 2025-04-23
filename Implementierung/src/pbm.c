#include "helpers/safe_malloc.h"
#include "pbm.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WHITESPACES "\t\n\x0b\x0c\r\x20" // TAB, LF, VT, FF, CR, space
#define LINE_END "\r\n"

// implemented spec: https://netpbm.sourceforge.net/doc/pbm.html

// fread wrapper that respects comments according to the spec
// return value is a pointer to where the char was written
// null if anything failed
char *next_char(char *result_char, FILE *stream) {
    if (!fread(result_char, 1, 1, stream)){
        return NULL;
    }
    // skip comments
    while (*result_char == '#') {
        while (!strchr(LINE_END, *result_char)) {
            if (!fread(result_char, 1, 1, stream)) {
               return NULL;
            }
        }
        if (!fread(result_char, 1, 1, stream)) {
               return NULL;
        }
    }

    return result_char;
}

// result value: amount of bytes skipped
// 0 means failure (either that there were no whitespaces to skip or that read failed)
size_t skip_whitespaces(FILE *stream) {
    char read_char;
    size_t bytes_read = 0;

    if (!next_char(&read_char, stream)) {
            return 0;
    }
    while (strchr(WHITESPACES, read_char)) {
        bytes_read += 1;
        if (!next_char(&read_char, stream)) {
            return 0;
        }
    }
    fseek(stream, -1, SEEK_CUR);
    return bytes_read;
}

// result value: amount of bytes read
// 0 means failure (either that the first char retured by read was not a dec digit or that read failed)
size_t parse_number(FILE *stream, size_t *result) {
    char read_char;
    size_t bytes_read = 0;

    if (!fread(&read_char, 1, 1, stream)) {
        return 0;
    }
    *result = 0;
    while (read_char >= '0' && read_char <= '9') {
        bytes_read += 1;

        *result *= 10;
        *result += read_char - '0';

        if (!fread(&read_char, 1, 1, stream)) {
            return 0;
        }
    }
    fseek(stream, -1, SEEK_CUR);
    return bytes_read;
}

// TODO: not sure but I think you could directly mmap the file into memory which might save some time
// this way we can just set result_struct->pixel_vals to a pointer into that mapped memory (and don't need to manually copy into a heap buffer)
int pbm_parse(char *file_name, PBM_Image *result_struct) {
    FILE *stream = fopen(file_name, "r");
    if (!stream) {
        return -1;
    }
    char *magic_buf = (char *)safe_malloc(2);
    char read_char;
    if (fread(magic_buf, 1, 2, stream) != 2) {
        return -2;
    };
    if (magic_buf[0] != 'P' || magic_buf[1] != '4') {
        return -3;
    }
    free(magic_buf);

    if(!skip_whitespaces(stream)) {
        return -4;
    }

    if (!parse_number(stream, &result_struct->width)) {
        return -5;
    }

    if(!skip_whitespaces(stream)) {
        return -6;
    }

    if (!parse_number(stream, &result_struct->height)) {
        return -7;
    }

    //sanity check
    if (result_struct->height == 0) {
        return -8;
    }
    if (result_struct->width == 0) {
        return -9;
    }

    if (!next_char(&read_char, stream)
        || !strchr(WHITESPACES, read_char))
    {
            return -10;
    }

    size_t buf_size = pbm_pixel_buf_size(result_struct->width, result_struct->height);
    result_struct->pixel_vals = (uint8_t *)safe_malloc(buf_size);
    if (fread(result_struct->pixel_vals, 1, buf_size, stream) != buf_size) {
            return -11;
    }

    fclose(stream);

    return 0;
}

int pbm_dump(char *file_name, size_t width, size_t height, uint8_t* pixel_vals) {
    FILE *stream = fopen(file_name, "w");
    if (!stream) {
        return -1;
    }

    if (fwrite("P4\n", 1, 3, stream) != 3) {
        return -2;
    }

    if(fprintf(stream, "%lu %lu\n", width, height) < 0) {
        return -3;
    }

    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);
    if(fwrite(pixel_vals, 1, pixel_buf_size, stream) != pixel_buf_size) {
        return -4;
    }
    fclose(stream);
    return 0;
}

size_t pbm_pixel_buf_size(size_t width, size_t height) {
    size_t bytes_width = (width / 8) + (width % 8 > 0);
    size_t result = bytes_width * height;
    if (result / bytes_width != height) {
        printf("Overflow detected, image dimensions too large");
        exit(-1);
    }
    return result;
}
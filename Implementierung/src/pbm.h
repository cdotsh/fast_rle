#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/select.h>

typedef struct PBM_Image {
    size_t width;
    size_t height;
    uint8_t* pixel_vals;
} PBM_Image;

// non 0 if parsing failed
int pbm_parse(char *file_name, PBM_Image *result_struct);
int pbm_dump(char *file_name, size_t width, size_t height, uint8_t* pixel_vals);

size_t pbm_pixel_buf_size(size_t width, size_t height);
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
// do run-length encoding and encode lengths as huffman codes

enum node_type {
    TYPE_INNER,
    TYPE_LEAF
};

typedef struct huffman_node huffman_node;

struct huffman_node {
    enum node_type type;

    // defined only if type == INNER, undefined otherwise
    huffman_node *children[2];

    // only used when building the tree
    // for inner nodes this value is the sum of it's children's frequencies
    size_t frequency;

    // only for leaf nodes
    size_t value;
};

typedef struct lookup_entry {
    size_t value;
    uint8_t *code;
    size_t code_bit_len;
} lookup_entry;

size_t rle_huffman_max_length(size_t width, size_t height) ;

size_t serialize_huffman_tree(uint8_t* rle_data, huffman_node root);
size_t deserialize_huffman_tree(const uint8_t* rle_data, size_t len, huffman_node **result);

void build_entries_recursive(lookup_entry *entry_arr, uint8_t *code, size_t depth, huffman_node *curr_node_ptr);

size_t run_length_encode_huffman(const uint8_t* img, size_t width, size_t height, uint8_t* rle_data);
void run_length_decode_huffman(const uint8_t* rle_data, size_t len, size_t width, size_t height, uint8_t* img);
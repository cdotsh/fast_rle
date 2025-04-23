#include "huffman.h"
#include "../pbm.h"
#include "../helpers/safe_malloc.h"
#include "../helpers/bit_ops_helpers.h"

#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>

// alphabet with (small) fixed length -> makes things easier + for large images we have a lot of values with the maximum value -> better compression

// has to be > 1 or things will break (also that wouldn't make sense)
// and how things are currently implemented encoding will become insanely slow if this is lets say > 16
static size_t HUFFMAN_LENGTH_BIT_SIZE = 7;

// https://en.wikipedia.org/wiki/Huffman_coding

size_t rle_huffman_max_length(size_t width, size_t height) {

    unsigned long tree_leaves_amount = (1 << HUFFMAN_LENGTH_BIT_SIZE);
    unsigned long tree_inner_nodes_amount = tree_leaves_amount - 1;
    unsigned long serialized_tree_bits = tree_inner_nodes_amount + (1 + HUFFMAN_LENGTH_BIT_SIZE) * tree_leaves_amount;
    // inner nodes can be serialized with 1 bit as they always have to have exactly 2 children:
    // 1st bit: indicates node type
    // leaf nodes are encoded in 1 + HUFFMAN_LENGTH_BIT_SIZE bits
    // 1st: indicates node type
    // HUFFMAN_LENGTH_BIT_SIZE next bits: encoded leaf value

    // https://groups.google.com/g/comp.compression/c/UPZbYB6qGU8/m/Rz8T-NfurusJ
    unsigned long max_huffman_code_length = tree_inner_nodes_amount;

    unsigned long pixel_buf_size = pbm_pixel_buf_size(width, height);
    unsigned long bits_to_encode = pixel_buf_size * 8;
    if (bits_to_encode / 8 != pixel_buf_size) {
        printf("computing bits_to_encode overflowed\n");
        exit(-1);
    }
    unsigned long max_rle_bit_size =  bits_to_encode * (max_huffman_code_length + 1);
    if (max_rle_bit_size / bits_to_encode != (max_huffman_code_length + 1)) {
        printf("computing max_rle_bit_size overflowed\n");
        exit(-1);
    }
    // https://stackoverflow.com/questions/199333/how-do-i-detect-unsigned-integer-overflow/1514309#1514309
    if (max_rle_bit_size > ULONG_MAX - serialized_tree_bits) {
        printf("computing max_rle_bit_len_total overflowed\n");
        exit(-1);
    }
    unsigned long max_bit_len_total = serialized_tree_bits + max_rle_bit_size;

    return max_bit_len_total / 8 + (max_bit_len_total % 8 > 0);
}

size_t run_length_encode_huffman(const uint8_t* img, size_t width, size_t height, uint8_t* rle_data) {
    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);

    size_t diff_len_vals_amount = 1 << HUFFMAN_LENGTH_BIT_SIZE;
    size_t freq_data[diff_len_vals_amount];
    for (size_t i=0; i<diff_len_vals_amount; i++) {
        freq_data[i] = 0;
    }

    bool current_color = (img[0] >> 7) & 1;
    size_t current_count = 0;
    for (size_t byte_idx = 0; byte_idx < pixel_buf_size; byte_idx++) {
        uint8_t read_byte = img[byte_idx];
        for (size_t i=0; i<8; i++) {
            bool pixel_value = (read_byte >> (7 - i)) & 1;
            if (pixel_value != current_color
                || current_count == diff_len_vals_amount - 1) {
                assert(current_count < diff_len_vals_amount);
                // since there should™ never be a length of 0 here index 0 will be unused but that's fine
                freq_data[current_count] += 1;
                current_color = pixel_value;
                current_count = 1;
            } else {
                current_count += 1;
            }
        }
    }

    freq_data[current_count] += 1;

    size_t nodes_arr_len = diff_len_vals_amount - 1;
    huffman_node leaves[nodes_arr_len];

    for (size_t i=0; i<nodes_arr_len; i++) {
        huffman_node new_leaf = {
            .type = TYPE_LEAF,
            .value = i + 1,
            .frequency = freq_data[i + 1],
            .children = {NULL, NULL}
        };
        leaves[i] = new_leaf;
    }

    huffman_node *node_ptrs[nodes_arr_len];
    for (size_t i=0; i<nodes_arr_len; i++) {
        node_ptrs[i] = &leaves[i];
    }

    size_t inner_nodes_amount = nodes_arr_len - 1;
    huffman_node inner_nodes[inner_nodes_amount];

    //printf("inner_nodes_amount: %lu\n", inner_nodes_amount);
    // yes, this is terribly inefficient for larger HUFFMAN_LENGTH_BIT_SIZE and could be made faster by sorting first or using a linked list
    // but that would add complexity which might not be needed so this will have to do for now
    for (size_t inner_node_idx=0; inner_node_idx<inner_nodes_amount; inner_node_idx++) {
        assert(nodes_arr_len >= 2);
        int smallest = -1;
        int second_smallest = -1;

        for (size_t i=0; i<nodes_arr_len; i++) {
            if (!node_ptrs[i]) {
                continue;
            }
            if (smallest == -1) {
                smallest = i;
                continue;
            }
            if (node_ptrs[i]->frequency <= node_ptrs[smallest]->frequency) {
                second_smallest = smallest;
                smallest = i;
            }
            if (second_smallest == -1) {
                second_smallest = i;
            }
        }
        assert(smallest >= 0);
        assert(second_smallest >= 0);
        assert(second_smallest != smallest);

        huffman_node new_node = {
            .type = TYPE_INNER,
            .frequency = node_ptrs[smallest]->frequency + node_ptrs[second_smallest]->frequency,
            .children = {node_ptrs[smallest], node_ptrs[second_smallest]},
            // should be ignored
            .value = 0
        };
        inner_nodes[inner_node_idx] = new_node;
        node_ptrs[second_smallest] = &inner_nodes[inner_node_idx];
        node_ptrs[smallest] = NULL;
    }

    #ifndef NDEBUG
    size_t count = 0;
    for (size_t i=0; i<nodes_arr_len; i++) {
        if (node_ptrs[i]) {
            //printf("non-null node_ptr idx: %lu\n", i);
            count += 1;
        }
    }
    assert(count == 1);
    #endif //NDEBUG

    huffman_node root_node = inner_nodes[inner_nodes_amount - 1];

    size_t rle_bit_idx = 0;
    rle_bit_idx += serialize_huffman_tree(rle_data, root_node);

    // build a lookup table for the huffman codes
    // this maps a length to a lookup entry which contains the code representing the length
    lookup_entry code_table[diff_len_vals_amount];

    uint8_t *current_code = (uint8_t *)safe_malloc(inner_nodes_amount / 8 + (inner_nodes_amount % 8 > 0));
    build_entries_recursive(code_table, current_code, 0, &root_node);
    free(current_code);

    // -----------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------

    // TODO: this is pretty much exactly the same code as the code that
    // 1. generates the frequency data
    // 2. encodes the tuples in rle_encode v0
    // so it would be nice if we would somehow not have to do this
    current_color = (img[0] >> 7) & 1;
    current_count = 0;
    for (size_t byte_idx = 0; byte_idx < pixel_buf_size; byte_idx++) {
        uint8_t read_byte = img[byte_idx];
        for (size_t bit_idx=0; bit_idx<8; bit_idx++) {
            bool pixel_value = (read_byte >> (7 - bit_idx)) & 1;
            if (pixel_value != current_color
                || current_count == diff_len_vals_amount - 1) {
                assert(current_count < diff_len_vals_amount);
                write_bit(rle_data, rle_bit_idx, current_color);
                rle_bit_idx += 1;
                lookup_entry *code_ptr = &code_table[current_count];
                //TODO: copying something bigger than bits will probably make this faster
                //printf("encoding: %d %lu ", current_color, current_count) ;
                for (size_t i=0; i<code_ptr->code_bit_len ; i++) {
                    bool next_bit = read_bit(code_ptr->code, i);
                    //printf("%d", next_bit);
                    write_bit(rle_data, rle_bit_idx, next_bit);
                    rle_bit_idx += 1;
                }
                //printf("\n");
                current_color = pixel_value;
                current_count = 1;
            } else {
                current_count += 1;
            }
        }
    }
    write_bit(rle_data, rle_bit_idx, current_color);
    rle_bit_idx += 1;
    lookup_entry *code_ptr = &code_table[current_count];
    //printf("encoding: %d %lu ", current_color, current_count) ;
    for (size_t i=0; i<code_ptr->code_bit_len ; i++) {
        bool next_bit = read_bit(code_ptr->code, i);
        write_bit(rle_data, rle_bit_idx, next_bit);
        rle_bit_idx += 1;
    }

    // free code table entries
    // start from one as 0 shouln't have occured, so no buffer should have been alloced
    for (size_t i=1; i<diff_len_vals_amount; i++) {
        free(code_table[i].code);
    }

    return (rle_bit_idx / 8) + (rle_bit_idx % 8 > 0);
}

void build_entries_recursive(lookup_entry *entry_arr, uint8_t *code, size_t depth, huffman_node *curr_node_ptr) {
    assert(curr_node_ptr->type == TYPE_INNER);
    for (int i=0; i<2; i++) {
        write_bit(code, depth, i);
        size_t next_depth = depth + 1;
        if (curr_node_ptr->children[i]->type == TYPE_LEAF) {
            size_t code_buf_size = next_depth / 8 + (next_depth % 8 > 0);
            uint8_t *saved_code = (uint8_t *)safe_malloc(code_buf_size);
            for (size_t byte_idx=0; byte_idx<code_buf_size; byte_idx++) {
                saved_code[byte_idx] = code[byte_idx];
            }
            lookup_entry new_entry = {.value=curr_node_ptr->children[i]->value, .code=saved_code, .code_bit_len=next_depth};
            entry_arr[curr_node_ptr->children[i]->value] = new_entry;
        } else {
            build_entries_recursive(entry_arr, code, next_depth,  curr_node_ptr->children[i]);
        }
    }
}

void run_length_decode_huffman(const uint8_t* rle_data, size_t len, size_t width, size_t height, uint8_t* img) {
    // deserialize huffman tree from input data

    huffman_node *root;
    size_t rle_bit_idx = deserialize_huffman_tree(rle_data, len, &root);
    if (!rle_bit_idx) {
        printf("deserializing huffman tree failed");
        exit(-1);
    }

    size_t pixel_buf_size = pbm_pixel_buf_size(width, height);
    size_t expected_bit_amount = pixel_buf_size * 8;

    if (expected_bit_amount / 8 != pixel_buf_size) {
        printf("overflow detected\n");
        exit(-1);
    }
    size_t bits_written = 0;
    while (rle_bit_idx / 8 < len && bits_written < expected_bit_amount) {
        bool color = read_bit(rle_data, rle_bit_idx);
        rle_bit_idx += 1;
        // printf("decoding: %d ", color);
        huffman_node *current_node = root;
        while (rle_bit_idx / 8 < len && current_node && current_node->type == TYPE_INNER) {
            bool next_bit = read_bit(rle_data, rle_bit_idx);
            // printf("%d", next_bit);
            current_node = current_node->children[next_bit];
            rle_bit_idx += 1;
        }
        if (!current_node ||current_node->type != TYPE_LEAF) {
            printf("failed traversing huffman tree\n");
            exit(-1);
        }

        size_t amount = current_node->value;

        // printf(" -> %lu\n", amount);
        //printf("decoded: %d %lu at %lu len:%lu\n", color, amount, rle_bit_idx - HUFFMAN_LENGTH_BIT_SIZE - 1, len);
        if (bits_written + amount > expected_bit_amount) {
            printf("compressed file invalid\n");
            exit(-1);
        }

        set_n_bits(amount, img, bits_written, color);

        bits_written += amount;
    }

    free(root);

    if (bits_written != expected_bit_amount) {
        printf("Image dimensions and actual encoded bits don't match\n");
        exit(-1);
    }
}

enum serializer_state {
    STATE_NODE_START,
    STATE_ZERO_CHILD,
    STATE_ONE_CHILD,
    STATE_LEAF
};

size_t serialize_huffman_tree(uint8_t* rle_data, huffman_node root) {
    size_t total_node_amount = 2 * (1 << HUFFMAN_LENGTH_BIT_SIZE) - 1;
    size_t rle_bit_idx = 0;

    huffman_node *processing_stack[total_node_amount];
    size_t processing_stack_size = 1;
    processing_stack[0] = &root;

    enum serializer_state state = STATE_NODE_START;
    while (processing_stack_size > 0) {
        huffman_node *curr_node_ptr = processing_stack[processing_stack_size -1];
        switch (state) {
            case STATE_NODE_START: {
                bool node_is_inner = curr_node_ptr->type == TYPE_INNER;

                write_bit(rle_data, rle_bit_idx, node_is_inner);
                rle_bit_idx += 1;

                state = node_is_inner ? STATE_ZERO_CHILD : STATE_LEAF;
                break;
            }
            case STATE_ZERO_CHILD: {
                processing_stack[processing_stack_size] = curr_node_ptr->children[0];
                processing_stack_size += 1;

                state = STATE_NODE_START;
                break;
            }
            case STATE_ONE_CHILD: {
                assert(processing_stack_size > 0);
                processing_stack[processing_stack_size - 1] = curr_node_ptr->children[1];

                state = STATE_NODE_START;
                break;
            }
            case STATE_LEAF: {
                encode_n_bit_num(rle_data, rle_bit_idx, curr_node_ptr->value, HUFFMAN_LENGTH_BIT_SIZE);
                rle_bit_idx  += HUFFMAN_LENGTH_BIT_SIZE;
                processing_stack_size -= 1;

                state = STATE_ONE_CHILD;
                break;
            }
        }
    }
    return rle_bit_idx;
}

// return value: amount of bits read. zero indicates failure
size_t deserialize_huffman_tree(const uint8_t* rle_data, size_t len, huffman_node **result) {
    // this is the amount of nodes that this tree should have if we used HUFFMAN_LENGTH_BIT_SIZE
    size_t expected_length = 2 * ((1 << HUFFMAN_LENGTH_BIT_SIZE) - 1) - 1;
    //                                                                                                                    ^ this tree won't have a 0
    huffman_node *node_arr = (huffman_node *)safe_malloc(expected_length * sizeof(huffman_node));
    size_t node_arr_len = 0;

    // here we will store the inner nodes that havent yet processed their second child
    huffman_node *processing_stack[expected_length];
    size_t processing_stack_size = 0;

    size_t rle_bit_idx = 0;

    enum serializer_state state = STATE_NODE_START;
    while (node_arr_len < expected_length) {
        size_t required_length;
        if (state == STATE_LEAF) {
            required_length = HUFFMAN_LENGTH_BIT_SIZE;
        } else {
            required_length = 1;
        }
        if ((rle_bit_idx + required_length) >> 3 >= len) {
            goto failed;
        }

        switch (state) {
            case STATE_NODE_START: {
                bool type_bit = read_bit(rle_data, rle_bit_idx);
                rle_bit_idx += 1;
                state = type_bit ? STATE_ZERO_CHILD : STATE_LEAF;
                break;
            }
            case STATE_ZERO_CHILD: {
                huffman_node new_node = {
                    .type = TYPE_INNER,
                    // pointer to the node that will be created
                    .children = {&node_arr[node_arr_len + 1], NULL}
                };

                node_arr[node_arr_len] = new_node;
                node_arr_len += 1;

                // push this node onto the processing stack
                processing_stack[processing_stack_size] = &node_arr[node_arr_len - 1];
                processing_stack_size += 1;

                state = STATE_NODE_START;
                break;
            }
            case STATE_ONE_CHILD: {
                if (processing_stack_size == 0) {
                    goto failed;
                }

                // pop the top node ptr from the processing stack
                huffman_node *parent_node = processing_stack[processing_stack_size - 1];
                processing_stack_size -= 1;

                // pointer to the node that will be created
                parent_node->children[1] = &node_arr[node_arr_len];

                state = STATE_NODE_START;
                break;
            }
            case STATE_LEAF: {
                huffman_node new_node = {
                    .type = TYPE_LEAF,
                    .value = decode_n_bit_num(rle_data, rle_bit_idx, HUFFMAN_LENGTH_BIT_SIZE),
                };
                node_arr[node_arr_len] = new_node;
                node_arr_len += 1;
                rle_bit_idx += HUFFMAN_LENGTH_BIT_SIZE;

                state = STATE_ONE_CHILD;
                break;
            }
        }
    }

    if (processing_stack_size > 0) {
        goto failed;
    }

    *result = node_arr;
    return rle_bit_idx;
    failed:
    free(node_arr);
    return 0;
}
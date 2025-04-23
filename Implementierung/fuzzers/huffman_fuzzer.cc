#include <cstdint>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <fuzzer/FuzzedDataProvider.h>

// yes, you should usually include the header files instead of this
// but otherwise I'm getting weird linker errors and time is short :p
#include "../src/helpers/bit_ops_helpers.c"
#include "../src/helpers/safe_malloc.c"
#include "../src/pbm.c"
#include "../src/v2/huffman.c"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);

    // this uses LENGTH_BIT_SIZE so this must come after

    HUFFMAN_LENGTH_BIT_SIZE = provider.ConsumeIntegralInRange<size_t>(2, 10);
    // in compressed_format we make sure that the len provided is actually correct so we can make that assumption here
    size_t input_buf_len = provider.ConsumeIntegralInRange<size_t>(10, 1000);
    uint8_t *input_buf = (uint8_t *)calloc(1, input_buf_len);
     provider.ConsumeData(input_buf, input_buf_len);

    huffman_node *root_node;
    size_t serialized_bits_real = deserialize_huffman_tree(input_buf, input_buf_len, &root_node);
    if (serialized_bits_real) {
        uint tree_leaves_amount = (1 << HUFFMAN_LENGTH_BIT_SIZE);
        uint tree_inner_nodes_amount = tree_leaves_amount - 1;
        uint serialized_tree_bits_max = tree_inner_nodes_amount + (1 + HUFFMAN_LENGTH_BIT_SIZE) * tree_leaves_amount;
        uint8_t *serialized_buf = (uint8_t *)malloc(serialized_tree_bits_max / 8 + (serialized_tree_bits_max % 8 > 0));

        serialize_huffman_tree(serialized_buf, *root_node);

        for (int i=0; i<serialized_bits_real; i++) {
            assert(read_bit(input_buf, i) == read_bit(serialized_buf, i));
        }

        free(serialized_buf);
        free(root_node);
    }

    free(input_buf);
    return 0;
}

/*
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    size_t height = provider.ConsumeIntegralInRange<size_t>(1, 100);
    size_t width = provider.ConsumeIntegralInRange<size_t>(1, 100);

    // this uses LENGTH_BIT_SIZE so this must come after
    size_t rle_buf_max_size = rle_huffman_max_length(width, height);
    uint8_t *rle_buf = (uint8_t *)calloc(1, rle_buf_max_size);

    size_t img_buf_size = pbm_pixel_buf_size(width, height);
    uint8_t *img_buf = (uint8_t *)calloc(1, img_buf_size);
     provider.ConsumeData(img_buf, img_buf_size);

    size_t enc_ret_val = run_length_encode_huffman(img_buf, width, height, rle_buf);

    uint8_t *decode_buf = (uint8_t *)calloc(1, img_buf_size);
    run_length_decode_huffman(rle_buf, enc_ret_val, width, height, decode_buf);

    for (int i=0; i<img_buf_size; i++) {
        assert(img_buf[i] == decode_buf[i]);
    }

    free(rle_buf);
    free(decode_buf);
    free(img_buf);
    return 0;
}
*/
#include <cstdint.h>
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
#include "../src/v0/rle.c"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    size_t height = provider.ConsumeIntegralInRange<size_t>(1, 100);
    size_t width = provider.ConsumeIntegralInRange<size_t>(1, 100);

    LENGTH_BIT_SIZE = provider.ConsumeIntegralInRange<size_t>(2, 63);

    // this uses LENGTH_BIT_SIZE so this must come after
    size_t rle_buf_max_size = run_length_encode_max_length(width, height);
    uint8_t *rle_buf = (uint8_t *)malloc(rle_buf_max_size);

    size_t img_buf_size = pbm_pixel_buf_size(width, height);
    uint8_t *img_buf = (uint8_t *)malloc(img_buf_size);
     provider.ConsumeData(img_buf, img_buf_size);

    size_t enc_ret_val = run_length_encode(img_buf, width, height, rle_buf);

    uint8_t *decode_buf = (uint8_t *)malloc(img_buf_size);
    run_length_decode(rle_buf, enc_ret_val, width, height, decode_buf);

    for (int i=0; i<img_buf_size; i++) {
        assert(img_buf[i] == decode_buf[i]);
    }

    free(rle_buf);
    free(decode_buf);
    free(img_buf);
    return 0;
}

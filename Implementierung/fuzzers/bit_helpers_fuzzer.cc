#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "../src/helpers/bit_ops_helpers.c"

// uncomment once you get a crash to get further information
//#define PRINTPLS

/*
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  size_t buf_size = provider.ConsumeIntegralInRange<size_t>(1, 20);
  size_t bit_size = provider.ConsumeIntegralInRange<size_t>(1, buf_size * 8 > 63 ? 63 : buf_size * 8);
  size_t num = provider.ConsumeIntegralInRange<size_t>(1, ((size_t)1 << bit_size) - 1);
  size_t bit_offset = provider.ConsumeIntegralInRange<size_t>(0, buf_size * 8 - bit_size);
  uint8_t *a = (uint8_t *)malloc(buf_size);
  #ifdef PRINTPLS
  printf("num: %lu\n", num);
  printf("buf_size, bit_size: %lu %lu\n", buf_size, bit_size);
  printf("bit_offset: %lu\n", bit_offset);
  #endif // PRINTPLS
  encode_n_bit_num(a, bit_offset, num, bit_size);
  size_t decoded = decode_n_bit_num(a, bit_offset, bit_size);
  #ifdef PRINTPLS
  printf("decoded: %lu\n", decoded);
  #endif //PRINTPLS
  assert(decoded == num);
  free(a);
  return 0;
}
*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  size_t buf_size = provider.ConsumeIntegralInRange<size_t>(1, 20);
  size_t bit_size = provider.ConsumeIntegralInRange<size_t>(1, buf_size * 8 > 63 ? 63 : buf_size * 8);
  size_t num = provider.ConsumeIntegralInRange<size_t>(1, ((size_t)1 << bit_size) - 1);
  size_t bit_offset = provider.ConsumeIntegralInRange<size_t>(0, buf_size * 8 - bit_size);
  uint8_t *a = (uint8_t *)calloc(1, buf_size);
  uint8_t *b = (uint8_t *)calloc(1, buf_size);
  encode_n_bit_num(a, bit_offset, 1, 1);
  write_bit(b, bit_offset, 1);
  for (int i=0; i<buf_size; i++) {
    assert(a[i] == b[i]);
  }
  free(a);
  free(b);
  return 0;
}
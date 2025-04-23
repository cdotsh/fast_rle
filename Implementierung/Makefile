PROJECT_FILES=src/pbm.c src/compressed_format.c src/helpers/safe_malloc.c src/v0/rle.c src/v2/huffman.c src/helpers/bit_ops_helpers.c src/v1/rle_v1.c
WARNING_FLAGS=-Wall -Wextra
FUZZ_FLAGS =-g -fsanitize=address,fuzzer

main: $(PROJECT_FILES) main.c
	gcc -Ofast $(WARNING_FLAGS) -DNDEBUG -o $@ $^

debug: $(PROJECT_FILES) main.c
	clang $(WARNING_FLAGS) -g -fsanitize=address -O0 -o $@ $^

bit_ops_fuzzer:$(PROJECT_FILES) fuzzers/bit_helpers_fuzzer.cc
	clang $(WARNING_FLAGS) $(FUZZ_FLAGS) $^ -o $@

v0_fuzzer: $(PROJECT_FILES) fuzzers/v0_fuzzer.cc
	clang $(WARNING_FLAGS) $(FUZZ_FLAGS) $^ -o $@

v1_fuzzer: $(PROJECT_FILES) fuzzers/v1_fuzzer.cc
	clang $(WARNING_FLAGS) $(FUZZ_FLAGS) $^ -o $@

huffman_fuzzer: $(PROJECT_FILES) fuzzers/huffman_fuzzer.cc
	clang $(WARNING_FLAGS) $(FUZZ_FLAGS) $^ -o $@


clean:
	rm -f main debug bit_ops_fuzzer v0_fuzzer v1_fuzzer huffman_fuzzer

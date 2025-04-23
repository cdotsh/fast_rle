#pragma once
#include <stdlib.h>
// safe malloc replacements that evade the pain of having to check the return value every time
void *safe_malloc(size_t len);
void *safe_calloc(size_t amount, size_t size);
void *safe_realloc(void *old_ptr, size_t new_size);
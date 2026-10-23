#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct item { char data[64]; };

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    uint32_t count = 0x04000001u;
    size_t elem_size = sizeof(struct item);
    printf("[demo] count = %u, sizeof(item) = %zu\n", count, elem_size);

    size_t bytes;
    if (__builtin_mul_overflow((size_t)count, elem_size, &bytes)) {
        printf("[demo] count * sizeof(item) would overflow -- refusing the allocation safely\n");
        return 1;
    }
    printf("[demo] count * sizeof(item) computed in 64 bits = %zu bytes (no overflow)\n", bytes);

    struct item *v = malloc(bytes);
    if (!v) {
        printf("[demo] malloc returned NULL (this sandbox limits memory) -- that is a clean,\n");
        printf("       checked failure, not silent heap corruption like the vulnerable version\n");
        return 1;
    }
    printf("allocated correctly\n");
    free(v);
    return 0;
}

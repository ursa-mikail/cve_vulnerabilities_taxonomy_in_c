#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct item { char data[64]; };

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    uint32_t count = 0x04000001u; /* ~67,108,865 */
    uint32_t elem_size = (uint32_t)sizeof(struct item); /* 64 */
    printf("[demo] count = %u, sizeof(item) = %u\n", count, elem_size);

    uint32_t bytes32 = count * elem_size; /* VULNERABLE: 32-bit multiply wraps (CWE-190) */
    printf("[demo] count * sizeof(item) computed in 32 bits = %u bytes (wrapped!)\n", bytes32);

    struct item *v = malloc(bytes32);
    if (!v) { printf("malloc failed\n"); return 1; }

    printf("[demo] allocated only %u bytes, but writing as if %u elements fit...\n", bytes32, count);
    for (uint32_t i = 0; i < 5; i++) {
        memset(&v[i], 0x41, sizeof v[i]); /* heap overflow once the allocation is tiny */
    }
    printf("wrote 5 elements\n");
    free(v);
    return 0;
}

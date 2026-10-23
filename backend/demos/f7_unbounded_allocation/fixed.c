#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TOTAL (64 * 1024 * 1024) /* policy cap: 64 MB total for this demo */

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] growing the same buffer in 8 MB steps, now capped at %d MB\n", MAX_TOTAL / (1024 * 1024));
    size_t step = 8 * 1024 * 1024;
    size_t total = 0;
    while (total + step <= MAX_TOTAL) {
        char *chunk = malloc(step);
        if (!chunk) { printf("malloc failed unexpectedly\n"); return 1; }
        memset(chunk, 0x41, step);
        total += step;
        printf("[demo] allocated %zu MB so far...\n", total / (1024 * 1024));
        fflush(stdout);
        free(chunk); /* also release what we no longer need */
    }
    printf("[demo] reached the policy cap and stopped cleanly -- no exhaustion possible\n");
    return 0;
}

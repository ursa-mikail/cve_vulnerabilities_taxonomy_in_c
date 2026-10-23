#include <stdio.h>
#include <stdint.h>
#include <sys/random.h>

static int fill_random(uint8_t *out, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r < 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    uint8_t token1[16], token2[16];
    if (fill_random(token1, sizeof token1) != 0 || fill_random(token2, sizeof token2) != 0) {
        printf("getrandom failed\n");
        return 1;
    }
    printf("[demo] token 1 (OS CSPRNG): ");
    for (size_t i = 0; i < sizeof token1; i++) printf("%02x", token1[i]);
    printf("\n[demo] token 2 (OS CSPRNG): ");
    for (size_t i = 0; i < sizeof token2; i++) printf("%02x", token2[i]);
    printf("\n[demo] two calls a moment apart -- completely different, not derivable from the clock\n");
    return 0;
}

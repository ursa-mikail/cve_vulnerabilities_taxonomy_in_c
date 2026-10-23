#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    srand((unsigned)time(NULL)); /* VULNERABLE: CWE-338, seeded from the wall clock */
    unsigned token1 = rand();
    printf("[demo] token generated this instant: %u\n", token1);
    printf("[demo] an attacker who knows roughly when this ran can brute-force the seed\n");
    printf("       (there are only ~86,400 possible seeds per day) and reproduce this\n");
    printf("       \"random\" token without ever seeing it\n");

    srand((unsigned)time(NULL)); /* reseeding within the same second reproduces the token */
    unsigned token2 = rand();
    printf("[demo] token generated moments later, same clock second: %u\n", token2);
    if (token1 == token2)
        printf("[demo] IDENTICAL -- fully predictable from the clock alone\n");
    else
        printf("[demo] the clock ticked over between calls this run, but the principle still\n");
    printf("       holds: the token space is only as large as the number of possible seeds\n");
    return 0;
}

#include <stdio.h>

int step_hash(void)      { return 0; }
int step_params(void)    { return 0; }
int step_signature(void) { return -1; } /* still fails on purpose, to prove the fix catches it */

int verify(void) {
    int err = -1; /* FIX: fail closed by default */
    if (step_hash()      != 0) goto out;
    if (step_params()    != 0) goto out;
    if (step_signature() != 0) goto out;
    err = 0; /* success only if every step actually passed */
out:
    return err;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] verifying the same certificate with the INVALID SIGNATURE...\n");
    int result = verify();
    printf("verify() returned %d (0 = verified OK)\n", result);
    if (result != 0)
        printf("[demo] correctly rejected -- the bad signature was not skipped\n");
    return 0;
}

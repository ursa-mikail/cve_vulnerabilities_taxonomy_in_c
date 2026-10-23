#include <stdio.h>

int step_hash(void)      { return 0; }  /* 0 = success; placeholders for real crypto steps */
int step_params(void)    { return 0; }
int step_signature(void) { return -1; } /* this one SHOULD fail -- the signature is bad */

int verify(void) {
    int err = 0;
    if ((err = step_hash()) != 0)   goto fail;
    if ((err = step_params()) != 0) goto fail;
        goto fail;                           /* VULNERABLE: CWE-670, duplicated unconditional goto */
    if ((err = step_signature()) != 0)       /* never runs because of the line above */
        goto fail;
fail:
    return err; /* err is still 0 here -- reported as "success" */
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] verifying a certificate whose SIGNATURE IS INVALID...\n");
    int result = verify();
    printf("verify() returned %d (0 = verified OK)\n", result);
    if (result == 0)
        printf("[demo] BUG: accepted as valid even though step_signature() would have failed\n");
    return 0;
}

#include <stdio.h>
#include <string.h>

void wipe(char *buf) {
    printf("[demo] sizeof(buf) inside wipe() is %zu, because buf is a POINTER, not an array\n", sizeof(buf));
    memset(buf, 0, sizeof(buf)); /* VULNERABLE: CWE-467, clears only a few bytes */
}

static void dump(const char *label, const unsigned char *p, size_t n) {
    printf("%s:", label);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    char secret[32];
    memset(secret, 0, sizeof secret);
    strcpy(secret, "TOP-SECRET-KEY-MATERIAL");
    dump("before wipe", (unsigned char *)secret, sizeof secret);
    wipe(secret);
    dump("after  wipe", (unsigned char *)secret, sizeof secret);
    printf("[demo] bytes past the pointer size are still the secret -- the \"wipe\" did not work\n");
    return 0;
}

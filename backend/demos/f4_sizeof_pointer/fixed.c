#include <stdio.h>
#include <string.h>

void wipe(char *buf, size_t cap) {
    printf("[demo] wipe() now takes the real capacity (%zu bytes) explicitly\n", cap);
    memset(buf, 0, cap); /* FIX: correct size, not sizeof(pointer) */
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
    wipe(secret, sizeof secret);
    dump("after  wipe", (unsigned char *)secret, sizeof secret);
    printf("[demo] every byte is now 0x00 -- the secret is fully gone\n");
    return 0;
}

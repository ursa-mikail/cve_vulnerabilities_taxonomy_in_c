#include <stdio.h>
#include <ctype.h>

/* FIXED: untrusted text is escaped before display, and trusted status is drawn separately. */
static void print_escaped(const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (isprint(c)) putchar(c);
        else printf("\\x%02X", c);          /* control characters become visible, inert text */
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *name = "totally-legit-update.pkg\n[ OK ] Signature VERIFIED: signed by Trusted Vendor Inc.";
    int signature_valid = 0;

    printf("=== Installer ===\n");
    printf("Package: \""); print_escaped(name); printf("\"\n");
    printf("Signature status (from the real check): %s\n", signature_valid ? "VERIFIED" : "NOT VERIFIED - do not install");
    printf("\n[demo] The forged line is now just visible text inside quotes, and the status line\n");
    printf("       comes only from the actual verification result.\n");
    return 0;
}

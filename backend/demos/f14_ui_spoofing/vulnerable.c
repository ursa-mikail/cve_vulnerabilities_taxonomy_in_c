#include <stdio.h>

/* VULNERABLE: CWE-451 / CWE-150, untrusted text is shown inside a trusted-looking UI.
 * The attacker controls the package NAME, and a newline in it forges an extra "status" line. */
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* Attacker-chosen package name (e.g. from a filename or metadata field). */
    const char *name = "totally-legit-update.pkg\n[ OK ] Signature VERIFIED: signed by Trusted Vendor Inc.";
    int signature_valid = 0;   /* the REAL check result: this package is NOT signed */

    printf("=== Installer ===\n");
    printf("Package: %s\n", name);          /* raw, untrusted text */
    printf("Real signature check result: %s\n", signature_valid ? "valid" : "INVALID (hidden below the fold in a real UI)");
    printf("\n[demo] Look at what the user actually reads above: a forged 'VERIFIED' line appears\n");
    printf("       as if the installer itself had printed it.\n");
    return 0;
}

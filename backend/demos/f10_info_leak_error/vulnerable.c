#include <stdio.h>
#include <errno.h>
#include <string.h>

/* VULNERABLE: CWE-209, internal details sent straight to the "client" */
void send_error_to_client(const char *path) {
    printf("HTTP 500: open(\"%s\") failed: %s\n", path, strerror(errno));
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    const char *internal_path = "/var/app/secret-config/db-credentials.ini";
    FILE *f = fopen(internal_path, "r");
    if (!f) {
        send_error_to_client(internal_path);
        printf("[demo] the client now knows the exact internal file layout and that this\n");
        printf("       path exists, which helps an attacker map the server's internals\n");
    }
    return 0;
}

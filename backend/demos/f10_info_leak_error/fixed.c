#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>

/* FIX: generic message to the client, details only in the server-side log */
void log_internally(const char *path) {
    fprintf(stderr, "[server log] open(\"%s\") failed: %s\n", path, strerror(errno));
}

void send_error_to_client(void) {
    printf("HTTP 500: Internal error. Reference: %ld\n", (long)time(NULL));
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    const char *internal_path = "/var/app/secret-config/db-credentials.ini";
    FILE *f = fopen(internal_path, "r");
    if (!f) {
        log_internally(internal_path); /* server-side only */
        send_error_to_client();        /* client-side: no internals leaked */
        printf("[demo] the client sees only a reference number; the path and errno\n");
        printf("       stayed on the server side\n");
    }
    return 0;
}

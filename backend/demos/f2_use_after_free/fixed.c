#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    char *p = malloc(32);
    if (!p) return 1;
    strcpy(p, "secret-session-token");
    printf("[demo] allocated 32 bytes at %p and stored a token in it\n", (void *)p);
    free(p);
    p = NULL; /* FIX: never dereferenced again */
    printf("[demo] freed the block and cleared the pointer -- no further access\n");
    printf("p = %p (NULL, nothing to read)\n", (void *)p);
    return 0;
}

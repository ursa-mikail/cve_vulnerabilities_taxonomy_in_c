#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { T_NOTE = 1, T_USER = 2 };
struct note { int type; char text[8]; };                      /* 12 bytes */
struct user { int type; char *name; unsigned long name_len; }; /* 24 bytes: holds a POINTER at offset 8 */

static void show_user(void *obj) {
    struct user *u = obj;                                     /* VULNERABLE: trusts the caller's claim */
    printf("name_len=%lu name=%s\n", u->name_len, u->name);   /* reads attacker bytes as a pointer */
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct note *n = malloc(sizeof *n);
    n->type = T_NOTE;
    memcpy(n->text, "AAAAAAA", 8);                            /* attacker-controlled bytes */
    printf("[demo] object is a NOTE, but the message says it is a USER...\n");
    int claimed_type = T_USER;                                /* comes from untrusted input */
    if (claimed_type == T_USER) show_user(n);                 /* CWE-843: object used as the wrong type */
    free(n);
    return 0;
}

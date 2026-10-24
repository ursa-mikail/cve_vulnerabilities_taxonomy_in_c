#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { T_NOTE = 1, T_USER = 2 };
struct note { int type; char text[8]; };
struct user { int type; char *name; unsigned long name_len; };

static int show_user(void *obj) {
    if (*(int *)obj != T_USER) {                              /* FIXED: check the object's OWN tag */
        printf("[demo] refused: this object is not a user (tag=%d)\n", *(int *)obj);
        return -1;
    }
    struct user *u = obj;
    printf("name_len=%lu name=%s\n", u->name_len, u->name);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct note *n = malloc(sizeof *n);
    n->type = T_NOTE;
    memcpy(n->text, "AAAAAAA", 8);
    printf("[demo] object is a NOTE, but the message says it is a USER...\n");
    int claimed_type = T_USER;
    if (claimed_type == T_USER) show_user(n);
    free(n);
    return 0;
}

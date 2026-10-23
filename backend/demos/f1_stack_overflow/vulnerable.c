#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[16];
    printf("[demo] copying %zu bytes into a 16-byte stack buffer with strcpy()\n", strlen(name));
    strcpy(buf, name); /* VULNERABLE: no bounds check (CWE-121) */
    printf("buf = %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    const char *attacker_input =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    greet(attacker_input);
    printf("greet() returned normally (this line may never print)\n");
    return 0;
}

#include <stdio.h>
#include <string.h>

int greet(const char *name) {
    char buf[16];
    int n = snprintf(buf, sizeof buf, "%s", name);
    if (n < 0 || (size_t)n >= sizeof buf) {
        printf("[demo] input (%zu bytes) does not fit in the 16-byte buffer -- refusing it safely\n",
               strlen(name));
        return -1;
    }
    printf("buf = %s\n", buf);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    const char *attacker_input =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    greet(attacker_input);
    printf("greet() returned normally -- no overflow, no crash\n");
    return 0;
}

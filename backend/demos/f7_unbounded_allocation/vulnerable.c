#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] growing an unbounded buffer in 8 MB steps with NO cap (CWE-770/789)\n");
    size_t step = 8 * 1024 * 1024;
    size_t total = 0;
    for (;;) {
        char *chunk = malloc(step);
        if (!chunk) {
            printf("[demo] malloc finally failed after %zu MB -- a real server with no cap\n",
                   total / (1024 * 1024));
            printf("       and no resource limits could instead be OOM-killed by the kernel,\n");
            printf("       taking other processes down with it\n");
            return 1;
        }
        memset(chunk, 0x41, step); /* touch the memory so it is really committed */
        total += step;
        printf("[demo] allocated %zu MB so far...\n", total / (1024 * 1024));
        fflush(stdout);
    }
}

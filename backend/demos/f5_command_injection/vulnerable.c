#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ping_host(const char *host) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "echo pinging %s", host); /* VULNERABLE: CWE-78 */
    printf("[demo] running shell command: %s\n", cmd);
    system(cmd);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    const char *attacker_controlled_host = "example.com; echo INJECTED-COMMAND-RAN";
    ping_host(attacker_controlled_host);
    return 0;
}

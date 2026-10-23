#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <ctype.h>

int ping_host(const char *host) {
    if (host[0] == '\0' || host[0] == '-') return -1;
    for (const char *c = host; *c; c++) {
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '-') {
            printf("[demo] rejected host \"%s\" (contains a disallowed character)\n", host);
            return -1;
        }
    }
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execlp("echo", "echo", "pinging", host, (char *)NULL);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    const char *attacker_controlled_host = "example.com; echo INJECTED-COMMAND-RAN";
    printf("[demo] no shell involved; the whole string is ONE argument to echo, never parsed\n");
    ping_host(attacker_controlled_host);
    return 0;
}

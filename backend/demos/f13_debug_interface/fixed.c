#include <stdio.h>
#include <string.h>

/* FIXED: debug access is tied to the device lifecycle state, which is set by a one-way fuse. */
enum lifecycle { LC_DEVELOPMENT = 0, LC_PRODUCTION = 1 };
static const enum lifecycle fused_state = LC_PRODUCTION;   /* one-time-programmable: cannot go back */
static const char device_secret[] = "KEY-9F3A-77C1-AB02";

static const char *debug_read_secret(void) {
    if (fused_state != LC_DEVELOPMENT) return NULL;   /* fail closed in production */
    return device_secret;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("[demo] device lifecycle: PRODUCTION (shipped to customers)\n");
    printf("[demo] attacker connects a debug probe to the exposed header...\n");
    const char *s = debug_read_secret();
    if (s) printf("[attack] debug port answered. Device secret dumped: %s\n", s);
    else   printf("[safe] debug port is permanently disabled in production; request refused.\n");
    return 0;
}

#include <stdio.h>
#include <string.h>

/* VULNERABLE: CWE-1191, a debug port that ships enabled in production silicon/firmware.
 * This is a software model of a hardware/firmware design flaw: no code "bug" here --
 * the DESIGN left a privileged path open. */
#define DEBUG_PORT_ENABLED 1          /* never turned off for production units */
static const char device_secret[] = "KEY-9F3A-77C1-AB02";   /* normally burned in secure storage */

static const char *debug_read_secret(void) {
    if (!DEBUG_PORT_ENABLED) return NULL;
    return device_secret;             /* no authentication, no lifecycle check */
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("[demo] device lifecycle: PRODUCTION (shipped to customers)\n");
    printf("[demo] attacker connects a debug probe to the exposed header...\n");
    const char *s = debug_read_secret();
    if (s) printf("[attack] debug port answered. Device secret dumped: %s\n", s);
    else   printf("[safe] debug port is closed.\n");
    return 0;
}

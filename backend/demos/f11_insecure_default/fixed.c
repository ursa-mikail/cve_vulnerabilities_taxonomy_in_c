#include <stdio.h>
#include <string.h>

struct config { const char *bind_addr; int admin_enabled; const char *admin_password; };
struct config cfg = { "127.0.0.1", 0, NULL }; /* FIX: safe by default */

int config_validate(const struct config *c) {
    if (c->admin_enabled && (!c->admin_password || strlen(c->admin_password) < 12))
        return -1; /* fail closed: refuse to start in an unsafe configuration */
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] starting with the FIXED default configuration:\n");
    printf("  bind_addr      = %s\n", cfg.bind_addr);
    printf("  admin_enabled  = %d\n", cfg.admin_enabled);
    if (config_validate(&cfg) != 0) {
        printf("[demo] refusing to start: admin panel enabled without a real password\n");
        return 1;
    }
    printf("[demo] local-only, admin off by default -- an operator must deliberately opt in\n");
    printf("       and set a real password before anything is exposed\n");
    return 0;
}

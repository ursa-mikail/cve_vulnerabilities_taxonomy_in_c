#include <stdio.h>
#include <string.h>

/* VULNERABLE: CWE-1188, ships open to the world with admin on and no password */
struct config { const char *bind_addr; int admin_enabled; const char *admin_password; };
struct config cfg = { "0.0.0.0", 1, "" };

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] starting with the SHIPPED DEFAULT configuration:\n");
    printf("  bind_addr      = %s\n", cfg.bind_addr);
    printf("  admin_enabled  = %d\n", cfg.admin_enabled);
    printf("  admin_password = \"%s\" (%zu characters)\n", cfg.admin_password, strlen(cfg.admin_password));
    printf("[demo] the server starts anyway -- an open admin panel, reachable from anywhere,\n");
    printf("       protected by an empty password\n");
    return 0;
}

#include <stdio.h>
#include <string.h>

struct record { unsigned id; unsigned owner_id; char body[64]; };

struct record db[] = {
    {1, 100, "Alice's private note: medication schedule"},
    {2, 200, "Bob's private note: salary negotiation plan"},
};
#define DB_LEN (sizeof(db) / sizeof(db[0]))

const struct record *find(unsigned id) {
    for (size_t i = 0; i < DB_LEN; i++)
        if (db[i].id == id) return &db[i];
    return NULL;
}

/* VULNERABLE: CWE-639 / CWE-862, never checks that the caller owns the record */
void get_record(unsigned requester_id, unsigned record_id) {
    (void)requester_id;
    const struct record *r = find(record_id);
    if (!r) { printf("404 not found\n"); return; }
    printf("200 OK: %s\n", r->body);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    printf("[demo] user 100 (Alice) is logged in and asks for record #2 (Bob's note)\n");
    get_record(/*requester_id=*/100, /*record_id=*/2);
    printf("[demo] Alice just read Bob's private note -- no ownership check ever happened\n");
    return 0;
}

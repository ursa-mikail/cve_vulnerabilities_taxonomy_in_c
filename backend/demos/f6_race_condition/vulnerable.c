#include <stdio.h>
#include <pthread.h>

#define THREADS 8
#define INCREMENTS 200000

long balance = 0; /* VULNERABLE: CWE-362, unsynchronized shared counter */

void *deposit(void *arg) {
    (void)arg;
    for (int i = 0; i < INCREMENTS; i++)
        balance += 1; /* read-modify-write is not atomic */
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* flush every line, even if this demo crashes */
    pthread_t t[THREADS];
    for (int i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, deposit, NULL);
    for (int i = 0; i < THREADS; i++) pthread_join(t[i], NULL);

    long expected = (long)THREADS * INCREMENTS;
    printf("expected balance = %ld\n", expected);
    printf("actual   balance = %ld\n", balance);
    if (balance != expected)
        printf("[demo] LOST UPDATES: %ld increments vanished due to the race\n", expected - balance);
    else
        printf("[demo] no lost updates on this particular run (races are timing-dependent)\n");
    return 0;
}

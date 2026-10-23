#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>

#define THREADS 8
#define INCREMENTS 200000

_Atomic long balance = 0; /* FIX: atomic increment, no lost updates */

void *deposit(void *arg) {
    (void)arg;
    for (int i = 0; i < INCREMENTS; i++)
        atomic_fetch_add(&balance, 1);
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
    printf("[demo] atomic_fetch_add guarantees every increment counts\n");
    return 0;
}

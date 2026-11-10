/* Synthetic layout benchmark for the relation matrix.
 *
 * This is not the game.  It compares three ways to walk ~683 x 683 relation
 * records while reading the fields used by the daily loops:
 *
 *   ptrs: one separately allocated Rel per pair, array of pointers
 *   aos:  one contiguous array of Rel
 *   soa:  eight contiguous int32 arrays, one per field
 *
 * Build: gcc -O2 -march=native -o microbench microbench.c
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N 683
#define PAIRS (N * N)
#define FIELDS 8
#define REPS 40

typedef struct {
    int32_t f[FIELDS];
} Rel;

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void shuffle(int *a, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = a[i]; a[i] = a[j]; a[j] = t;
    }
}

static int64_t walk_ptrs(Rel **p, const int *perm) {
    int64_t sum = 0;
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                const Rel *x = p[perm[i] * N + perm[j]];
                sum += x->f[1] + x->f[2] + x->f[5] + x->f[6] + x->f[7];
            }
    return sum;
}

static int64_t walk_aos(Rel *p, const int *perm) {
    int64_t sum = 0;
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                const Rel *x = &p[perm[i] * N + perm[j]];
                sum += x->f[1] + x->f[2] + x->f[5] + x->f[6] + x->f[7];
            }
    return sum;
}

static int64_t walk_soa(int32_t *soa[FIELDS], const int *perm) {
    int64_t sum = 0;
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                int k = perm[i] * N + perm[j];
                sum += soa[1][k] + soa[2][k] + soa[5][k] + soa[6][k] + soa[7][k];
            }
    return sum;
}

int main(void) {
    srand(12345);
    Rel **ptrs = malloc((size_t)PAIRS * sizeof(*ptrs));
    Rel *aos = malloc((size_t)PAIRS * sizeof(*aos));
    int32_t *soa[FIELDS];
    int *perm = malloc((size_t)N * sizeof(*perm));
    if (!ptrs || !aos || !perm) return 2;
    for (int f = 0; f < FIELDS; f++) {
        soa[f] = malloc((size_t)PAIRS * sizeof(int32_t));
        if (!soa[f]) return 2;
    }
    for (int i = 0; i < N; i++) perm[i] = i;
    shuffle(perm, N);

    for (int i = 0; i < PAIRS; i++) {
        ptrs[i] = malloc(sizeof(Rel));
        if (!ptrs[i]) return 2;
        for (int f = 0; f < FIELDS; f++) {
            int32_t v = (int32_t)((i * 131 + f * 17) & 0xFFFF);
            ptrs[i]->f[f] = v;
            aos[i].f[f] = v;
            soa[f][i] = v;
        }
    }

    volatile int64_t sink;
    double t0, t1;
    t0 = now_ns(); sink = walk_ptrs(ptrs, perm); t1 = now_ns();
    double ptrs_ns = (t1 - t0) / (double)(REPS * PAIRS);
    t0 = now_ns(); sink = walk_aos(aos, perm); t1 = now_ns();
    double aos_ns = (t1 - t0) / (double)(REPS * PAIRS);
    t0 = now_ns(); sink = walk_soa(soa, perm); t1 = now_ns();
    double soa_ns = (t1 - t0) / (double)(REPS * PAIRS);

    printf("pairs=%d reps=%d\n", PAIRS, REPS);
    printf("ptrs %.3f ns/pair\n", ptrs_ns);
    printf("aos  %.3f ns/pair\n", aos_ns);
    printf("soa  %.3f ns/pair\n", soa_ns);
    printf("checksum %lld\n", (long long)sink);
    return 0;
}

/* Native 683 x 683 relation-matrix fixture.
 *
 * This is not the game.  It reproduces the layout question from README.md:
 *
 *   ptrs     466,489 separately allocated Rel objects + array of pointers
 *   aos      one contiguous Rel block (layout A) read directly
 *   aos_ptr  the same block, reached through the original pointer array
 *   soa      eight contiguous int32 arrays, one per field
 *
 * The fixture runs the same deterministic daily pass on every layout and
 * checks:
 *
 *   - identical field values after the pass (checksums and full comparison);
 *   - no pointer invalidation (pointer arrays are byte-identical afterwards);
 *   - layout A keeps pointer identity and adjacency into the backing block;
 *   - canaries before and after every allocation survive the pass.
 *
 * Then it times the pass.  Field indices stand in for the offsets listed in
 * README.md until those offsets are confirmed against the binary.
 *
 * Build (correctness): gcc -std=c11 -O1 -g -fsanitize=address,undefined \
 *                            -fno-omit-frame-pointer -o fixture-asan fixture.c
 * Build (timing):      gcc -std=c11 -O2 -march=native -o fixture fixture.c
 *
 * Run: ./fixture [--json] [--reps N] [--rounds N] [--correctness-only]
 */
#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N 683
#define PAIRS ((size_t)N * (size_t)N)
#define FIELDS 8
#define MAX_ROUNDS 32

#define GUARD_WORDS 8
#define GUARD_BYTES (GUARD_WORDS * sizeof(uint32_t))
#define GUARD_VALUE 0xC0FFEEu

typedef struct {
    int32_t f[FIELDS];
} Rel;

typedef struct {
    double median;
    double p95;
} Stat;

static uint64_t rng_state;

static void die(const char *what) {
    fprintf(stderr, "fixture: %s\n", what);
    exit(2);
}

static void *xmalloc(size_t bytes) {
    void *p = malloc(bytes);
    if (p == NULL) {
        die("out of memory");
    }
    return p;
}

static double now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        die("clock_gettime failed");
    }
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static uint64_t next_u64(void) {
    uint64_t z = (rng_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void make_perm(int *perm) {
    for (int i = 0; i < N; i++) {
        perm[i] = i;
    }
    rng_state = UINT64_C(0x123456789ABCDEF0);
    for (int i = N - 1; i > 0; i--) {
        int j = (int)(next_u64() % (uint64_t)(i + 1));
        int tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}

static int32_t initial_value(size_t k, int field) {
    uint64_t x = (uint64_t)k * UINT64_C(0x9E3779B97F4A7C15) +
                 (uint64_t)field * UINT64_C(0xD6E8FEB86659FD93);
    x ^= x >> 33;
    x *= UINT64_C(0xFF51AFD7ED558CCD);
    x ^= x >> 33;
    return (int32_t)(x & 0xFFFFu);
}

static void fill_guard(unsigned char *raw, size_t bytes) {
    uint32_t *head = (uint32_t *)raw;
    uint32_t *tail = (uint32_t *)(raw + GUARD_BYTES + bytes);
    for (size_t i = 0; i < GUARD_WORDS; i++) {
        head[i] = GUARD_VALUE;
        tail[i] = GUARD_VALUE;
    }
}

static int guard_ok(const unsigned char *raw, size_t bytes) {
    const uint32_t *head = (const uint32_t *)raw;
    const uint32_t *tail = (const uint32_t *)(raw + GUARD_BYTES + bytes);
    for (size_t i = 0; i < GUARD_WORDS; i++) {
        if (head[i] != GUARD_VALUE || tail[i] != GUARD_VALUE) {
            return 0;
        }
    }
    return 1;
}

static void *guarded_alloc(size_t bytes, unsigned char **raw_out) {
    unsigned char *raw = xmalloc(GUARD_BYTES + bytes + GUARD_BYTES);
    fill_guard(raw, bytes);
    *raw_out = raw;
    return raw + GUARD_BYTES;
}

static Rel *rel_alloc(void) {
    unsigned char *raw = xmalloc(GUARD_BYTES + sizeof(Rel) + GUARD_BYTES);
    fill_guard(raw, sizeof(Rel));
    return (Rel *)(raw + GUARD_BYTES);
}

static int rel_guard_ok(const Rel *rel) {
    const unsigned char *raw = (const unsigned char *)rel - GUARD_BYTES;
    return guard_ok(raw, sizeof(Rel));
}

static void init_ptrs(Rel **ptrs) {
    for (size_t k = 0; k < PAIRS; k++) {
        Rel *rel = rel_alloc();
        for (int f = 0; f < FIELDS; f++) {
            rel->f[f] = initial_value(k, f);
        }
        ptrs[k] = rel;
    }
}

static void init_aos(Rel *aos, Rel **ptrs) {
    for (size_t k = 0; k < PAIRS; k++) {
        for (int f = 0; f < FIELDS; f++) {
            aos[k].f[f] = initial_value(k, f);
        }
        ptrs[k] = &aos[k];
    }
}

static void init_soa(int32_t *soa[FIELDS]) {
    for (size_t k = 0; k < PAIRS; k++) {
        for (int f = 0; f < FIELDS; f++) {
            soa[f][k] = initial_value(k, f);
        }
    }
}

/* One deterministic daily pass.  It reads the five hot fields, writes one
 * field on the current pair and one on a neighbouring country, mirroring the
 * read/write mix of Country_PrePass and the daily loops. */
static int64_t pass_ptrs(Rel *const *ptrs, const int *perm) {
    int64_t sum = 0;
    for (int i = 0; i < N; i++) {
        size_t row = (size_t)perm[i] * N;
        int next_i = (i + 1 == N) ? 0 : i + 1;
        size_t next_row = (size_t)perm[next_i] * N;
        for (int j = 0; j < N; j++) {
            size_t k = row + (size_t)perm[j];
            size_t ok = next_row + (size_t)perm[j];
            Rel *x = ptrs[k];
            Rel *o = ptrs[ok];
            int32_t t = x->f[1] + x->f[2] + x->f[5] + x->f[6] + x->f[7];
            x->f[3] = (x->f[3] + t + (int32_t)(i + j) + 1) & 0xFFFF;
            o->f[4] = (o->f[4] + (x->f[3] & 7)) & 0xFFFF;
            sum += x->f[3] + o->f[4];
        }
    }
    return sum;
}

static int64_t pass_aos(Rel *aos, const int *perm) {
    int64_t sum = 0;
    for (int i = 0; i < N; i++) {
        size_t row = (size_t)perm[i] * N;
        int next_i = (i + 1 == N) ? 0 : i + 1;
        size_t next_row = (size_t)perm[next_i] * N;
        for (int j = 0; j < N; j++) {
            Rel *x = &aos[row + (size_t)perm[j]];
            Rel *o = &aos[next_row + (size_t)perm[j]];
            int32_t t = x->f[1] + x->f[2] + x->f[5] + x->f[6] + x->f[7];
            x->f[3] = (x->f[3] + t + (int32_t)(i + j) + 1) & 0xFFFF;
            o->f[4] = (o->f[4] + (x->f[3] & 7)) & 0xFFFF;
            sum += x->f[3] + o->f[4];
        }
    }
    return sum;
}

static int64_t pass_soa(int32_t *const soa[FIELDS], const int *perm) {
    int64_t sum = 0;
    for (int i = 0; i < N; i++) {
        size_t row = (size_t)perm[i] * N;
        int next_i = (i + 1 == N) ? 0 : i + 1;
        size_t next_row = (size_t)perm[next_i] * N;
        for (int j = 0; j < N; j++) {
            size_t k = row + (size_t)perm[j];
            size_t ok = next_row + (size_t)perm[j];
            int32_t t = soa[1][k] + soa[2][k] + soa[5][k] +
                        soa[6][k] + soa[7][k];
            int32_t v = (soa[3][k] + t + (int32_t)(i + j) + 1) & 0xFFFF;
            int32_t ov = (soa[4][ok] + (v & 7)) & 0xFFFF;
            soa[3][k] = v;
            soa[4][ok] = ov;
            sum += v + ov;
        }
    }
    return sum;
}

static uint64_t digest_ptrs(Rel *const *ptrs) {
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t k = 0; k < PAIRS; k++) {
        for (int f = 0; f < FIELDS; f++) {
            h ^= (uint32_t)ptrs[k]->f[f];
            h *= UINT64_C(1099511628211);
        }
    }
    return h;
}

static uint64_t digest_aos(const Rel *aos) {
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t k = 0; k < PAIRS; k++) {
        for (int f = 0; f < FIELDS; f++) {
            h ^= (uint32_t)aos[k].f[f];
            h *= UINT64_C(1099511628211);
        }
    }
    return h;
}

static uint64_t digest_soa(int32_t *const soa[FIELDS]) {
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t k = 0; k < PAIRS; k++) {
        for (int f = 0; f < FIELDS; f++) {
            h ^= (uint32_t)soa[f][k];
            h *= UINT64_C(1099511628211);
        }
    }
    return h;
}

static int compare_layouts(Rel *const *ptrs, const Rel *aos,
                           int32_t *const soa[FIELDS]) {
    for (size_t k = 0; k < PAIRS; k++) {
        for (int f = 0; f < FIELDS; f++) {
            if (ptrs[k]->f[f] != aos[k].f[f] ||
                ptrs[k]->f[f] != soa[f][k]) {
                fprintf(stderr,
                        "fixture: value mismatch at pair %zu field %d "
                        "(ptrs=%" PRId32 " aos=%" PRId32 " soa=%" PRId32 ")\n",
                        k, f, ptrs[k]->f[f], aos[k].f[f], soa[f][k]);
                return 0;
            }
        }
    }
    return 1;
}

static int check_aos_pointers(const Rel *aos, Rel *const *aos_ptrs) {
    for (size_t k = 0; k < PAIRS; k++) {
        if (aos_ptrs[k] != &aos[k]) {
            fprintf(stderr, "fixture: pointer identity failed at pair %zu\n", k);
            return 0;
        }
        if (k + 1 < PAIRS && aos_ptrs[k + 1] != aos_ptrs[k] + 1) {
            fprintf(stderr, "fixture: adjacency failed at pair %zu\n", k);
            return 0;
        }
    }
    return 1;
}

static int check_rel_guards(Rel *const *ptrs) {
    for (size_t k = 0; k < PAIRS; k++) {
        if (!rel_guard_ok(ptrs[k])) {
            fprintf(stderr, "fixture: canary failed for pair %zu\n", k);
            return 0;
        }
    }
    return 1;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

static double percentile(const double *sorted, int n, double p) {
    if (n <= 0) {
        return 0.0;
    }
    if (n == 1) {
        return sorted[0];
    }
    double pos = (double)(n - 1) * p;
    int lo = (int)pos;
    int hi = (lo + 1 < n) ? lo + 1 : lo;
    double frac = pos - (double)lo;
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

static Stat stat_from(const double *values, int n) {
    double sorted[MAX_ROUNDS];
    memcpy(sorted, values, (size_t)n * sizeof(*sorted));
    qsort(sorted, (size_t)n, sizeof(*sorted), cmp_double);
    Stat s;
    s.median = percentile(sorted, n, 0.5);
    s.p95 = percentile(sorted, n, 0.95);
    return s;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [--json] [--reps N] [--rounds N] [--correctness-only]\n",
            argv0);
}

int main(int argc, char **argv) {
    int json = 0;
    int correctness_only = 0;
    int reps = 10;
    int rounds = 5;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json = 1;
        } else if (strcmp(argv[i], "--correctness-only") == 0) {
            correctness_only = 1;
        } else if (strcmp(argv[i], "--reps") == 0 && i + 1 < argc) {
            reps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rounds") == 0 && i + 1 < argc) {
            rounds = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (reps < 1 || rounds < 1 || rounds > MAX_ROUNDS) {
        usage(argv[0]);
        return 2;
    }

    int *perm = xmalloc((size_t)N * sizeof(*perm));
    make_perm(perm);

    unsigned char *ptrs_raw = NULL;
    Rel **ptrs = guarded_alloc(PAIRS * sizeof(*ptrs), &ptrs_raw);
    init_ptrs(ptrs);

    unsigned char *aos_raw = NULL;
    Rel *aos = guarded_alloc(PAIRS * sizeof(*aos), &aos_raw);
    unsigned char *aos_ptrs_raw = NULL;
    Rel **aos_ptrs = guarded_alloc(PAIRS * sizeof(*aos_ptrs), &aos_ptrs_raw);
    init_aos(aos, aos_ptrs);

    unsigned char *soa_raw[FIELDS] = {0};
    int32_t *soa[FIELDS];
    for (int f = 0; f < FIELDS; f++) {
        soa[f] = guarded_alloc(PAIRS * sizeof(*soa[f]), &soa_raw[f]);
    }
    init_soa(soa);

    Rel **ptrs_before = xmalloc(PAIRS * sizeof(*ptrs_before));
    Rel **aos_ptrs_before = xmalloc(PAIRS * sizeof(*aos_ptrs_before));
    memcpy(ptrs_before, ptrs, PAIRS * sizeof(*ptrs_before));
    memcpy(aos_ptrs_before, aos_ptrs, PAIRS * sizeof(*aos_ptrs_before));

    int64_t check_ptrs = pass_ptrs(ptrs, perm);
    int64_t check_aos = pass_aos(aos, perm);
    int64_t check_soa = pass_soa(soa, perm);

    uint64_t digest_p = digest_ptrs(ptrs);
    uint64_t digest_a = digest_aos(aos);
    uint64_t digest_s = digest_soa(soa);

    int values_equal = compare_layouts(ptrs, aos, soa);
    int pointers_stable =
        memcmp(ptrs_before, ptrs, PAIRS * sizeof(*ptrs_before)) == 0 &&
        memcmp(aos_ptrs_before, aos_ptrs,
               PAIRS * sizeof(*aos_ptrs_before)) == 0;
    int pointer_identity = check_aos_pointers(aos, aos_ptrs);
    int guards_ok =
        guard_ok(ptrs_raw, PAIRS * sizeof(*ptrs)) &&
        guard_ok(aos_raw, PAIRS * sizeof(*aos)) &&
        guard_ok(aos_ptrs_raw, PAIRS * sizeof(*aos_ptrs)) &&
        check_rel_guards(ptrs);
    for (int f = 0; f < FIELDS; f++) {
        guards_ok = guards_ok &&
                    guard_ok(soa_raw[f], PAIRS * sizeof(*soa[f]));
    }

    int ok = values_equal && pointers_stable && pointer_identity && guards_ok &&
             check_ptrs == check_aos && check_ptrs == check_soa &&
             digest_p == digest_a && digest_p == digest_s;

    if (!json) {
        printf("pairs=%zu fields=%d reps=%d rounds=%d\n",
               PAIRS, FIELDS, reps, rounds);
        printf("checksums: ptrs=%" PRId64 " aos=%" PRId64 " soa=%" PRId64 "\n",
               check_ptrs, check_aos, check_soa);
        printf("digests:   ptrs=%016" PRIx64 " aos=%016" PRIx64
               " soa=%016" PRIx64 "\n",
               digest_p, digest_a, digest_s);
        printf("values_equal=%s pointers_stable=%s pointer_identity=%s "
               "guards_ok=%s\n",
               values_equal ? "yes" : "no",
               pointers_stable ? "yes" : "no",
               pointer_identity ? "yes" : "no",
               guards_ok ? "yes" : "no");
    }

    if (!ok) {
        if (!json) {
            printf("correctness: FAIL\n");
        } else {
            printf("{\"correctness\":{\"ok\":false}}\n");
        }
        return 1;
    }

    if (correctness_only) {
        if (json) {
            printf("{\"pairs\":%zu,\"fields\":%d,\"correctness\":{\"ok\":true,"
                   "\"values_equal\":true,\"pointers_stable\":true,"
                   "\"pointer_identity\":true,\"guards_ok\":true,"
                   "\"checksum_ptrs\":%" PRId64 ",\"checksum_aos\":%" PRId64
                   ",\"checksum_soa\":%" PRId64 "}}\n",
                   PAIRS, FIELDS, check_ptrs, check_aos, check_soa);
        } else {
            printf("correctness: OK\n");
        }
        return 0;
    }

    enum { L_PTRS, L_AOS, L_AOS_PTR, L_SOA, L_COUNT };
    static const char *const names[L_COUNT] = {"ptrs", "aos", "aos_ptr", "soa"};
    double samples[L_COUNT][MAX_ROUNDS];
    volatile uint64_t sink = 0;

    for (int round = 0; round < rounds; round++) {
        for (int q = 0; q < L_COUNT; q++) {
            int layout = (q + round) % L_COUNT;
            int64_t sum = 0;
            double t0 = now_ns();
            for (int rep = 0; rep < reps; rep++) {
                switch (layout) {
                case L_PTRS:
                    sum += pass_ptrs(ptrs, perm);
                    break;
                case L_AOS:
                    sum += pass_aos(aos, perm);
                    break;
                case L_AOS_PTR:
                    sum += pass_ptrs(aos_ptrs, perm);
                    break;
                case L_SOA:
                    sum += pass_soa(soa, perm);
                    break;
                }
            }
            double t1 = now_ns();
            sink ^= (uint64_t)sum;
            samples[layout][round] =
                (t1 - t0) / ((double)reps * (double)PAIRS);
        }
    }

    Stat stats[L_COUNT];
    for (int layout = 0; layout < L_COUNT; layout++) {
        stats[layout] = stat_from(samples[layout], rounds);
    }

    int guards_after =
        guard_ok(ptrs_raw, PAIRS * sizeof(*ptrs)) &&
        guard_ok(aos_raw, PAIRS * sizeof(*aos)) &&
        guard_ok(aos_ptrs_raw, PAIRS * sizeof(*aos_ptrs)) &&
        check_rel_guards(ptrs);
    for (int f = 0; f < FIELDS; f++) {
        guards_after = guards_after &&
                       guard_ok(soa_raw[f], PAIRS * sizeof(*soa[f]));
    }
    if (!guards_after) {
        fprintf(stderr, "fixture: canary failed after timing pass\n");
        return 1;
    }

    if (json) {
        printf("{\"pairs\":%zu,\"fields\":%d,\"reps\":%d,\"rounds\":%d,"
               "\"correctness\":{\"ok\":true,\"values_equal\":true,"
               "\"pointers_stable\":true,\"pointer_identity\":true,"
               "\"guards_ok\":true,\"checksum_ptrs\":%" PRId64
               ",\"checksum_aos\":%" PRId64 ",\"checksum_soa\":%" PRId64
               ",\"digest_ptrs\":\"%016" PRIx64 "\",\"digest_aos\":\"%016"
               PRIx64 "\",\"digest_soa\":\"%016" PRIx64 "\"},\n",
               PAIRS, FIELDS, reps, rounds, check_ptrs, check_aos, check_soa,
               digest_p, digest_a, digest_s);
        printf(" \"timings_ns_per_pair\":{");
        for (int layout = 0; layout < L_COUNT; layout++) {
            printf("%s\"%s\":{\"median\":%.3f,\"p95\":%.3f}",
                   layout ? "," : "", names[layout],
                   stats[layout].median, stats[layout].p95);
        }
        printf("}}\n");
    } else {
        printf("timings (ns/pair, median / p95 over %d rounds):\n", rounds);
        for (int layout = 0; layout < L_COUNT; layout++) {
            printf("  %-8s %7.3f / %7.3f\n", names[layout],
                   stats[layout].median, stats[layout].p95);
        }
        printf("correctness: OK\n");
    }

    return 0;
}

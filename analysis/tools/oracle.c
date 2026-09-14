/* oracle.c -- native crackme verifier.
 *
 * Computes, for a candidate password, exactly what the binary computes:
 *
 *   MAC  = sponge(buf40(pw))                  (0x65A0, 1000 iterations)
 *   s5   = P4(s4 ^ MAC)
 *   s6   = P5(s5 ^ buf40[16..31])
 *   s7   = P6(s6 ^ (buf40[32..39]|0x80|0*7))
 *   pass <=> s7[0..7] == e6a0ef2284734165
 *
 * s4 and the three permutations come from data/gate_rounds.bin, which
 * tools/emit_rounds.py derives from the decoded VM program.  The sponge here is
 * a transcription of tools/sponge.py, which is byte-exact against the Unicorn
 * capture of the real binary.
 *
 *   gcc -O2 -o /tmp/oracle analysis/tools/oracle.c
 *   /tmp/oracle analysis/data/gate_rounds.bin test123
 *   /tmp/oracle analysis/data/gate_rounds.bin -bench 20000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static const uint8_t T1[16] = {0x6c,0x9f,0x1a,0xb7,0x35,0xe3,0x48,0x7d,
                               0x51,0x13,0x2b,0xc7,0x8e,0xb2,0x4f,0x63};
static const uint8_t T2[16] = {0x51,0x13,0x2b,0xc7,0x8e,0xb2,0x4f,0x63,
                               0xc9,0x3b,0xbd,0x11,0x94,0x43,0xeb,0xdf};

static inline uint8_t rotl8(uint8_t v, int k)
{
    k &= 7;
    return k ? (uint8_t)((v << k) | (v >> (8 - k))) : v;
}

/* 0x60B0 on the 8-byte window at s[win..win+7], table index off */
static void f60b0_win(uint8_t *s, int win, int off)
{
    int b = win;
    for (int k = 0; k < 4; k++) { uint8_t t = s[b+k]; s[b+k] = s[b+4+k]; s[b+4+k] = t; }
    uint8_t a = s[b], bv = s[b+1], c = s[b+2], d = s[b+3], A = s[b+4], D = s[b+7];
    uint8_t an = rotl8((uint8_t)(a + bv), bv & 7) ^ T1[off % 8];
    uint8_t bn = rotl8((uint8_t)(bv + D), c & 7);
    uint8_t cn = rotl8((uint8_t)(c - d),  d & 7) ^ T2[off % 8];
    uint8_t dn = rotl8((uint8_t)(cn + d), A & 7) ^ T1[(off + 3) % 8];
    s[b] = an; s[b+1] = bn; s[b+2] = cn; s[b+3] = dn;
}

/* pairwise rotations, sequential: s[i] uses the NEW s[8+i] */
static void pairwise(uint8_t *s)
{
    for (int i = 0; i < 8; i++) {
        s[8+i] = rotl8(s[8+i], s[i] & 7);
        s[i]   = rotl8(s[i],   s[8+i] & 7);
    }
}

static inline void f5e20(uint8_t *s, int ctr)
{
    f60b0_win(s, 0, ctr);
    f60b0_win(s, 8, ctr);
    pairwise(s);
}

/* 0x65A0: 1000 iterations of an 18-round keyed permutation */
static void sponge_mac(const uint8_t *pw, int n, uint8_t out[16])
{
    uint8_t buf[40];
    memset(buf, 0, 40);
    memcpy(buf, pw, n);
    buf[n] = 0x80;
    const uint8_t *head = buf, *key = buf + 16, *tail = buf + 32;
    uint8_t prev[16] = {0}, st[16];
    for (int it = 0; it < 1000; it++) {
        for (int i = 0; i < 16; i++) st[i] = (uint8_t)(head[i] ^ prev[i]);
        for (int c = 0; c < 6; c++) f5e20(st, c);
        for (int i = 0; i < 16; i++) st[i] ^= key[i];      /* 0x5C10 */
        for (int l = 0; l < 6; l++) f5e20(st, l);
        for (int k = 0; k < 8; k++) st[k] ^= tail[k];
        for (int c = 0; c < 6; c++) f5e20(st, c);
        memcpy(prev, st, 16);
    }
    memcpy(out, prev, 16);
}

/* ---- the three password-dependent VM rounds ----------------------------- */
typedef struct { uint16_t op; uint8_t c1, c2, c3, c4, c5; } __attribute__((packed)) Op;

static uint8_t g_s4[16], g_C[8];
static Op    *g_ops[3];
static int    g_n[3];

static void load_rounds(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    char magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "GATE", 4)) {
        fprintf(stderr, "%s: bad magic\n", path); exit(2);
    }
    if (fread(g_s4, 1, 16, f) != 16 || fread(g_C, 1, 8, f) != 8) {
        fprintf(stderr, "%s: truncated header\n", path); exit(2);
    }
    for (int r = 0; r < 3; r++) {
        uint32_t n;
        if (fread(&n, 4, 1, f) != 1) { fprintf(stderr, "truncated\n"); exit(2); }
        g_n[r] = (int)n;
        g_ops[r] = malloc(sizeof(Op) * n);
        if (fread(g_ops[r], sizeof(Op), n, f) != n) {
            fprintf(stderr, "%s: truncated round %d\n", path, r); exit(2);
        }
    }
    fclose(f);
}

/* one VM round: absorb a 16-byte block, then run the permutation.
 * 0x1310 (STORE) only writes the window and round 6 has no LOAD, so it is a
 * register-level no-op here (asserted by emit_rounds.py). */
static void run_round(int r, const uint8_t blk[16], uint8_t R[32])
{
    for (int i = 0; i < 16; i++) R[i] ^= blk[i];
    const Op *o = g_ops[r];
    int n = g_n[r];
    for (int i = 0; i < n; i++) {
        switch (o[i].op) {
        case 0x1020: R[o[i].c1] ^= o[i].c2; break;
        case 0x10C0: R[o[i].c1] ^= R[o[i].c2]; break;
        case 0x10E0: R[o[i].c1] = (uint8_t)(R[o[i].c1] + R[o[i].c2]); break;
        case 0x1110: R[o[i].c1] = (uint8_t)(R[o[i].c1] - R[o[i].c2]); break;
        case 0x1180: R[o[i].c1] = rotl8(R[o[i].c1], R[o[i].c2] & 7); break;
        default: break;                    /* 0x1390 nop, 0x1310 store */
        }
    }
}

static int gate(const uint8_t *pw, int n, uint8_t mac[16], uint8_t out[8])
{
    uint8_t buf40[40];
    memset(buf40, 0, 40);
    memcpy(buf40, pw, n);
    buf40[n] = 0x80;

    sponge_mac(pw, n, mac);

    uint8_t R[32];
    memset(R, 0, 32);
    memcpy(R, g_s4, 16);
    run_round(0, mac, R);
    run_round(1, buf40 + 16, R);
    uint8_t b6[16];
    memcpy(b6, buf40 + 32, 8);
    b6[8] = 0x80;
    memset(b6 + 9, 0, 7);
    run_round(2, b6, R);
    memcpy(out, R, 8);
    return memcmp(out, g_C, 8) == 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <gate_rounds.bin> <pw>... | -bench N\n", argv[0]);
        return 2;
    }
    load_rounds(argv[1]);

    if (!strcmp(argv[2], "-bench")) {
        long N = atol(argv[3]);
        uint8_t mac[16], out[8], pw[8];
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        long hits = 0;
        for (long i = 0; i < N; i++) {
            for (int k = 0; k < 8; k++) pw[k] = (uint8_t)((i >> (8 * (k % 4))) + k);
            hits += gate(pw, 8, mac, out);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
        printf("%ld passwords in %.3f s  ->  %.0f /s  (%.1f us each), hits=%ld\n",
               N, dt, N / dt, 1e6 * dt / N, hits);
        return 0;
    }

    int rc = 1;
    for (int i = 2; i < argc; i++) {
        int n = (int)strlen(argv[i]);
        if (n < 1 || n > 39) { printf("%-24s  rejected by the length gate\n", argv[i]); continue; }
        uint8_t mac[16], out[8];
        int pass = gate((const uint8_t *)argv[i], n, mac, out);
        printf("%-24s MAC=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
               " gate=%02x%02x%02x%02x%02x%02x%02x%02x %s\n",
               argv[i],
               mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],mac[6],mac[7],
               mac[8],mac[9],mac[10],mac[11],mac[12],mac[13],mac[14],mac[15],
               out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7],
               pass ? "*** PASS ***" : "");
        if (pass) rc = 0;
    }
    return rc;
}

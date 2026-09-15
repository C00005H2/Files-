/* AutoIt EA06 container: LAME keystream decrypt + LZSS decompress.
 *
 *   usage: ./autodec <seed> <in.bin> <out.bin>
 *
 * in.bin  : the encrypted resource payload (as stored in the EA06 container)
 * out.bin : the decompressed AutoIt token stream
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ---------------- LAME PRNG (as used by AutoIt EA06) ---------------- */
static uint32_t grp1[17];
static int c0, c1;

static uint32_t rol32(uint32_t x, int y)
{
    y &= 31;
    if (y == 0)
        return x;
    return (uint32_t)((x << y) | (x >> (32 - y)));
}

static double fpusht(void)
{
    uint32_t rolled = (uint32_t)((rol32(grp1[c0], 9) + rol32(grp1[c1], 13)) & 0xFFFFFFFFu);
    grp1[c0] = rolled;
    if (c0 == 0) c0 = 16; else c0--;
    if (c1 == 0) c1 = 16; else c1--;

    uint32_t low  = (uint32_t)(rolled << 20);
    uint32_t high = (uint32_t)((rolled >> 12) | 0x3FF00000u);
    uint8_t b[8];
    memcpy(b, &low, 4);
    memcpy(b + 4, &high, 4);
    double v;
    memcpy(&v, b, 8);
    return v - 1.0;
}

static void lame_srand(uint32_t seed)
{
    for (int i = 0; i < 17; i++) {
        seed = (uint32_t)(1u - (uint32_t)(seed * 0x53A9B4FBu));
        grp1[i] = seed;
    }
    c0 = 0;
    c1 = 10;
    for (int i = 0; i < 9; i++)
        fpusht();
}

static void lame_stream(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fpusht();
        double v = fpusht() * 256.0;
        long x = (long)v;             /* truncation toward zero, value >= 0 */
        buf[i] ^= (uint8_t)(x & 0xFF);
    }
}

static uint32_t adler32(const uint8_t *data, size_t len)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (uint32_t)((b << 16) | a);
}

/* ---------------- bit reader (MSB first, as in the ripper) ---------------- */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
    uint64_t acc;
    int bits;
} BR;

static inline uint32_t getbits(BR *br, int n)
{
    while (br->bits < n) {
        uint64_t byte = br->pos < br->len ? br->p[br->pos++] : 0;
        br->acc = (br->acc << 8) | byte;
        br->bits += 8;
    }
    br->bits -= n;
    return (uint32_t)((br->acc >> br->bits) & ((n == 32) ? 0xFFFFFFFFu : ((1ull << n) - 1)));
}

static uint32_t read_match_len(BR *br)
{
    static const uint32_t lengths[5] = {3, 6, 13, 44, 299};
    static const int      bitsv[5]   = {2, 3, 5, 8, 8};
    static const uint32_t morev[5]   = {3, 7, 31, 255, 255};

    uint32_t length = 0, length_add = 0;
    int i = 0;
    for (i = 0; i < 5; i++) {
        length = lengths[i];
        length_add = getbits(br, bitsv[i]);
        if (length_add != morev[i])
            break;
    }
    if (i == 5) {
        uint32_t more = morev[4];
        int bits = bitsv[4];
        for (;;) {
            length += more;
            length_add = getbits(br, bits);
            if (length_add != more)
                break;
        }
    }
    return length + length_add;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <seed> <in.bin> <out.bin>\n", argv[0]);
        return 2;
    }
    uint32_t seed = (uint32_t)strtoul(argv[1], NULL, 0);
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("open in"); return 1; }
    fseek(f, 0, SEEK_END);
    long clen = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *cpr = malloc((size_t)clen);
    if (!cpr || fread(cpr, 1, (size_t)clen, f) != (size_t)clen) { perror("read"); return 1; }
    fclose(f);

    lame_srand(seed);
    lame_stream(cpr, (size_t)clen);
    printf("adler32(decrypted) = %08x  (expected 8be484e7)\n", adler32(cpr, (size_t)clen));

    if (clen < 8 || memcmp(cpr, "EA06", 4) != 0) {
        fprintf(stderr, "bad compressed magic: %02x%02x%02x%02x\n", cpr[0], cpr[1], cpr[2], cpr[3]);
        return 1;
    }
    uint32_t usize = ((uint32_t)cpr[4] << 24) | ((uint32_t)cpr[5] << 16) |
                     ((uint32_t)cpr[6] << 8) | (uint32_t)cpr[7];
    printf("uncompressed size = %u\n", usize);

    uint8_t *out = malloc((size_t)usize + 16);
    if (!out) { perror("malloc out"); return 1; }
    size_t o = 0;

    BR br = {cpr + 8, (size_t)clen - 8, 0, 0, 0};
    uint64_t literals = 0, matches = 0;

    while (o < usize) {
        if (getbits(&br, 1) == 1) {
            out[o++] = (uint8_t)getbits(&br, 8);
            literals++;
        } else {
            uint32_t offset = getbits(&br, 15);
            uint32_t mlen = read_match_len(&br);
            size_t src = (offset == 0) ? 0 : o - offset;
            for (uint32_t k = 0; k < mlen && o < usize; k++)
                out[o++] = out[src + k];
            matches++;
        }
    }
    printf("literals=%llu matches=%llu out=%zu\n",
           (unsigned long long)literals, (unsigned long long)matches, o);

    f = fopen(argv[3], "wb");
    if (!f) { perror("open out"); return 1; }
    fwrite(out, 1, o, f);
    fclose(f);
    uint32_t lines = (uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                     ((uint32_t)out[2] << 16) | ((uint32_t)out[3] << 24);
    printf("token lines_no = %u\n", lines);
    return 0;
}

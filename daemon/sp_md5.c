#include "sp_md5.h"
#include "sp_util.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define ROTL(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); (a) = ROTL((a), (s)); (a) += (b);

static void md5_block(sp_md5_ctx *ctx, const uint8_t *p)
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) |
               ((uint32_t)p[i * 4 + 2] << 16) | ((uint32_t)p[i * 4 + 3] << 24);
    uint32_t a = ctx->a, b = ctx->b, c = ctx->c, d = ctx->d;

    STEP(F, a, b, c, d, x[0], 0xd76aa478, 7)  STEP(F, d, a, b, c, x[1], 0xe8c7b756, 12)
    STEP(F, c, d, a, b, x[2], 0x242070db, 17) STEP(F, b, c, d, a, x[3], 0xc1bdceee, 22)
    STEP(F, a, b, c, d, x[4], 0xf57c0faf, 7)  STEP(F, d, a, b, c, x[5], 0x4787c62a, 12)
    STEP(F, c, d, a, b, x[6], 0xa8304613, 17) STEP(F, b, c, d, a, x[7], 0xfd469501, 22)
    STEP(F, a, b, c, d, x[8], 0x698098d8, 7)  STEP(F, d, a, b, c, x[9], 0x8b44f7af, 12)
    STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17) STEP(F, b, c, d, a, x[11], 0x895cd7be, 22)
    STEP(F, a, b, c, d, x[12], 0x6b901122, 7) STEP(F, d, a, b, c, x[13], 0xfd987193, 12)
    STEP(F, c, d, a, b, x[14], 0xa679438e, 17) STEP(F, b, c, d, a, x[15], 0x49b40821, 22)

    STEP(G, a, b, c, d, x[1], 0xf61e2562, 5)  STEP(G, d, a, b, c, x[6], 0xc040b340, 9)
    STEP(G, c, d, a, b, x[11], 0x265e5a51, 14) STEP(G, b, c, d, a, x[0], 0xe9b6c7aa, 20)
    STEP(G, a, b, c, d, x[5], 0xd62f105d, 5)  STEP(G, d, a, b, c, x[10], 0x02441453, 9)
    STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14) STEP(G, b, c, d, a, x[4], 0xe7d3fbc8, 20)
    STEP(G, a, b, c, d, x[9], 0x21e1cde6, 5)  STEP(G, d, a, b, c, x[14], 0xc33707d6, 9)
    STEP(G, c, d, a, b, x[3], 0xf4d50d87, 14) STEP(G, b, c, d, a, x[8], 0x455a14ed, 20)
    STEP(G, a, b, c, d, x[13], 0xa9e3e905, 5) STEP(G, d, a, b, c, x[2], 0xfcefa3f8, 9)
    STEP(G, c, d, a, b, x[7], 0x676f02d9, 14) STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20)

    STEP(H, a, b, c, d, x[5], 0xfffa3942, 4)  STEP(H, d, a, b, c, x[8], 0x8771f681, 11)
    STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16) STEP(H, b, c, d, a, x[14], 0xfde5380c, 23)
    STEP(H, a, b, c, d, x[1], 0xa4beea44, 4)  STEP(H, d, a, b, c, x[4], 0x4bdecfa9, 11)
    STEP(H, c, d, a, b, x[7], 0xf6bb4b60, 16) STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23)
    STEP(H, a, b, c, d, x[13], 0x289b7ec6, 4) STEP(H, d, a, b, c, x[0], 0xeaa127fa, 11)
    STEP(H, c, d, a, b, x[3], 0xd4ef3085, 16) STEP(H, b, c, d, a, x[6], 0x04881d05, 23)
    STEP(H, a, b, c, d, x[9], 0xd9d4d039, 4)  STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11)
    STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16) STEP(H, b, c, d, a, x[2], 0xc4ac5665, 23)

    STEP(I, a, b, c, d, x[0], 0xf4292244, 6)  STEP(I, d, a, b, c, x[7], 0x432aff97, 10)
    STEP(I, c, d, a, b, x[14], 0xab9423a7, 15) STEP(I, b, c, d, a, x[5], 0xfc93a039, 21)
    STEP(I, a, b, c, d, x[12], 0x655b59c3, 6) STEP(I, d, a, b, c, x[3], 0x8f0ccc92, 10)
    STEP(I, c, d, a, b, x[10], 0xffeff47d, 15) STEP(I, b, c, d, a, x[1], 0x85845dd1, 21)
    STEP(I, a, b, c, d, x[8], 0x6fa87e4f, 6)  STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10)
    STEP(I, c, d, a, b, x[6], 0xa3014314, 15) STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21)
    STEP(I, a, b, c, d, x[4], 0xf7537e82, 6)  STEP(I, d, a, b, c, x[11], 0xbd3af235, 10)
    STEP(I, c, d, a, b, x[2], 0x2ad7d2bb, 15) STEP(I, b, c, d, a, x[9], 0xeb86d391, 21)

    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
}

void sp_md5_init(sp_md5_ctx *c)
{
    c->a = 0x67452301;
    c->b = 0xefcdab89;
    c->c = 0x98badcfe;
    c->d = 0x10325476;
    c->len = 0;
    c->used = 0;
}

void sp_md5_update(sp_md5_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    c->len += n;
    while (n) {
        size_t k = 64 - c->used;
        if (k > n)
            k = n;
        memcpy(c->buf + c->used, p, k);
        c->used += k;
        p += k;
        n -= k;
        if (c->used == 64) {
            md5_block(c, c->buf);
            c->used = 0;
        }
    }
}

void sp_md5_final(sp_md5_ctx *c, uint8_t out[16])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sp_md5_update(c, &pad, 1);
    pad = 0;
    while (c->used != 56)
        sp_md5_update(c, &pad, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++)
        lb[i] = (uint8_t)(bits >> (8 * i));
    sp_md5_update(c, lb, 8);
    uint32_t v[4] = { c->a, c->b, c->c, c->d };
    for (int i = 0; i < 4; i++) {
        out[i * 4] = (uint8_t)v[i];
        out[i * 4 + 1] = (uint8_t)(v[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(v[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(v[i] >> 24);
    }
}

void sp_md5_hex(const char *s, char out[33])
{
    sp_md5_ctx c;
    uint8_t d[16];
    sp_md5_init(&c);
    sp_md5_update(&c, s, strlen(s));
    sp_md5_final(&c, d);
    for (int i = 0; i < 16; i++)
        sprintf(out + i * 2, "%02x", d[i]);
    out[32] = 0;
}

/* ---- digest ---- */

/* Reads one auth-param value (quoted or token) for `name` from a challenge. */
static int auth_param(const char *hv, const char *name, char *out, size_t n)
{
    size_t nl = strlen(name);
    const char *p = hv;
    while (*p) {
        while (*p == ' ' || *p == ',' || *p == '\t')
            p++;
        const char *k = p;
        while (*p && *p != '=' && *p != ',' && *p != ' ')
            p++;
        size_t kl = (size_t)(p - k);
        while (*p == ' ')
            p++;
        if (*p != '=') {
            /* scheme word ("Digest") or a bare token */
            continue;
        }
        p++;
        while (*p == ' ')
            p++;
        const char *v;
        size_t vl;
        if (*p == '"') {
            v = ++p;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1])
                    p++;
                p++;
            }
            vl = (size_t)(p - v);
            if (*p == '"')
                p++;
        } else {
            v = p;
            while (*p && *p != ',' && *p != ' ')
                p++;
            vl = (size_t)(p - v);
        }
        if (kl == nl && sp_strncaseeq(k, name, nl)) {
            if (vl >= n)
                vl = n - 1;
            memcpy(out, v, vl);
            out[vl] = 0;
            return 1;
        }
    }
    return 0;
}

int sp_challenge_parse(const char *hv, sp_challenge *ch)
{
    memset(ch, 0, sizeof *ch);
    while (*hv == ' ')
        hv++;
    if (!sp_strncaseeq(hv, "Digest", 6))
        return -1;
    hv += 6;
    if (!auth_param(hv, "nonce", ch->nonce, sizeof ch->nonce))
        return -1;
    auth_param(hv, "realm", ch->realm, sizeof ch->realm);
    auth_param(hv, "opaque", ch->opaque, sizeof ch->opaque);
    if (!auth_param(hv, "algorithm", ch->algorithm, sizeof ch->algorithm))
        strcpy(ch->algorithm, "MD5");
    char qop[64] = "", stale[16] = "";
    if (auth_param(hv, "qop", qop, sizeof qop)) {
        /* qop="auth,auth-int" -> we only do auth */
        for (char *t = qop; *t; t++)
            *t = (char)tolower((unsigned char)*t);
        const char *a = strstr(qop, "auth");
        while (a) {
            if ((a == qop || a[-1] == ',' || a[-1] == ' ') &&
                (a[4] == 0 || a[4] == ',' || a[4] == ' '))
                ch->qop_auth = 1;
            a = strstr(a + 4, "auth");
        }
    }
    if (auth_param(hv, "stale", stale, sizeof stale))
        ch->stale = sp_strcaseeq(stale, "true");
    if (!sp_strcaseeq(ch->algorithm, "MD5"))
        return -2;     /* MD5-sess / SHA-256 not supported */
    return 0;
}

int sp_digest_build(char *out, size_t n, const sp_challenge *ch, const char *method,
                    const char *uri, const char *user, const char *pass, uint32_t *nc)
{
    char tmp[1024], ha1[33], ha2[33], resp[33];
    snprintf(tmp, sizeof tmp, "%s:%s:%s", user, ch->realm, pass);
    sp_md5_hex(tmp, ha1);
    memset(tmp, 0, sizeof tmp);
    snprintf(tmp, sizeof tmp, "%s:%s", method, uri);
    sp_md5_hex(tmp, ha2);

    char cnonce[17];
    char ncs[9];
    if (ch->qop_auth) {
        sp_rand_hex(cnonce, 16);
        (*nc)++;
        snprintf(ncs, sizeof ncs, "%08x", *nc);
        snprintf(tmp, sizeof tmp, "%s:%s:%s:%s:auth:%s", ha1, ch->nonce, ncs, cnonce, ha2);
    } else {
        snprintf(tmp, sizeof tmp, "%s:%s:%s", ha1, ch->nonce, ha2);
    }
    sp_md5_hex(tmp, resp);
    memset(ha1, 0, sizeof ha1);

    int k = snprintf(out, n,
                     "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", "
                     "response=\"%s\", algorithm=MD5",
                     user, ch->realm, ch->nonce, uri, resp);
    if (k < 0 || (size_t)k >= n)
        return -1;
    if (ch->qop_auth)
        k += snprintf(out + k, n - (size_t)k, ", cnonce=\"%s\", nc=%s, qop=auth", cnonce, ncs);
    if (ch->opaque[0] && (size_t)k < n)
        k += snprintf(out + k, n - (size_t)k, ", opaque=\"%s\"", ch->opaque);
    return (size_t)k < n ? 0 : -1;
}

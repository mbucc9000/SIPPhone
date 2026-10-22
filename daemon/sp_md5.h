/* MD5 (RFC 1321) and SIP digest authentication (RFC 2617 / RFC 3261 22.4). */
#ifndef SP_MD5_H
#define SP_MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t a, b, c, d;
    uint64_t len;
    uint8_t  buf[64];
    size_t   used;
} sp_md5_ctx;

void sp_md5_init(sp_md5_ctx *c);
void sp_md5_update(sp_md5_ctx *c, const void *data, size_t n);
void sp_md5_final(sp_md5_ctx *c, uint8_t out[16]);
void sp_md5_hex(const char *s, char out[33]);

/* A parsed WWW-Authenticate / Proxy-Authenticate challenge. */
typedef struct {
    char realm[128];
    char nonce[256];
    char opaque[256];
    char algorithm[32];
    int  qop_auth;      /* server offered qop=auth */
    int  stale;
} sp_challenge;

int sp_challenge_parse(const char *hv, sp_challenge *ch);   /* 0 ok */

/* Builds the full Authorization / Proxy-Authorization header value
   ("Digest username=..., ...") into out. nc is incremented when qop is used. */
int sp_digest_build(char *out, size_t n, const sp_challenge *ch, const char *method,
                    const char *uri, const char *user, const char *pass, uint32_t *nc);

#endif

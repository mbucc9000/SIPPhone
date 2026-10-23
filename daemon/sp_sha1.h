/* SHA-1 and HMAC-SHA1 (RFC 3174 / RFC 2104), portable C.
   Used for SRTP packet authentication (HMAC-SHA1-80). Host-testable against
   the published test vectors, and byte-identical on the device. */
#ifndef SP_SHA1_H
#define SP_SHA1_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[5];
    uint64_t len;        /* message length in bytes */
    uint8_t  buf[64];
    size_t   used;
} sp_sha1_ctx;

void sp_sha1_init(sp_sha1_ctx *c);
void sp_sha1_update(sp_sha1_ctx *c, const void *data, size_t n);
void sp_sha1_final(sp_sha1_ctx *c, uint8_t out[20]);

/* One-shot HMAC-SHA1. out_len bytes of the 20-byte MAC are written (SRTP uses 10). */
void sp_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                  uint8_t *out, size_t out_len);

#endif

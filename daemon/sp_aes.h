/* AES-128 block cipher + counter (CTR) mode, portable C (FIPS-197 / SP 800-38A).
   SRTP uses AES in counter mode (AES-CM). Host-testable against the NIST vectors;
   the device could use CommonCrypto, but 160 bytes per 20 ms is trivial in C and
   keeping one tested implementation avoids a second code path. */
#ifndef SP_AES_H
#define SP_AES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t rk[176];     /* 11 round keys for AES-128 */
} sp_aes;

void sp_aes128_init(sp_aes *a, const uint8_t key[16]);
void sp_aes_encrypt_block(const sp_aes *a, const uint8_t in[16], uint8_t out[16]);

/* XOR `len` bytes of AES-CTR keystream into buf, starting from the 16-byte counter
   `ctr` (incremented big-endian per block). ctr is advanced in place. */
void sp_aes_ctr_xor(const sp_aes *a, uint8_t ctr[16], uint8_t *buf, size_t len);

#endif

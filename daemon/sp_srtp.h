/* SRTP (RFC 3711) for the one G.711 stream: AES-CM-128 encryption +
   HMAC-SHA1-80 authentication, the AES_CM_128_HMAC_SHA1_80 crypto suite that
   VoIP.ms (SDES, RFC 4568) negotiates. One context per direction.
   Pure transform over sp_aes/sp_sha1, so it is host-testable end to end. */
#ifndef SP_SRTP_H
#define SP_SRTP_H

#include <stddef.h>
#include <stdint.h>
#include "sp_aes.h"

#define SP_SRTP_MASTER_KEY  16
#define SP_SRTP_MASTER_SALT 14
#define SP_SRTP_KEYING      (SP_SRTP_MASTER_KEY + SP_SRTP_MASTER_SALT)  /* 30 bytes = 40 base64 chars */
#define SP_SRTP_TAG         10   /* HMAC-SHA1-80 */

typedef struct {
    sp_aes   enc;                         /* session encryption key */
    uint8_t  salt[SP_SRTP_MASTER_SALT];   /* session salt */
    uint8_t  auth[20];                    /* session auth key */
    /* rollover + replay, keyed by the 16-bit RTP sequence number */
    uint32_t roc;
    uint16_t last_seq;
    int      seen;
    uint64_t replay;                      /* bitmap of the 64 indices below the high one */
    int      have_high;
    uint32_t high_roc;
    uint16_t high_seq;
} sp_srtp;

/* Derive session keys from a 30-byte master key||salt (one SDES key). */
void sp_srtp_init(sp_srtp *s, const uint8_t keying[SP_SRTP_KEYING]);

/* Protect an RTP packet in place: encrypt the payload and append the 10-byte tag.
   pkt holds `len` bytes with `cap` total room (needs len + SP_SRTP_TAG). Returns the
   new length, or -1 if there is no room / the packet is malformed. */
int sp_srtp_protect(sp_srtp *s, uint8_t *pkt, int len, int cap);

/* Unprotect in place: verify the tag, drop replays, decrypt. Returns the plaintext
   RTP length, or -1 (auth failure, replay, or malformed). */
int sp_srtp_unprotect(sp_srtp *s, uint8_t *pkt, int len);

/* base64 of exactly 30 bytes <-> the SDES inline value. */
int  sp_srtp_keying_from_b64(const char *b64, uint8_t out[SP_SRTP_KEYING]);
void sp_srtp_keying_to_b64(const uint8_t keying[SP_SRTP_KEYING], char out[41]);

#endif

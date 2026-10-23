/* Minimal SDP offer/answer for one audio stream (RFC 4566 / RFC 3264). */
#ifndef SP_SDP_H
#define SP_SDP_H

#include <stddef.h>
#include <stdint.h>

enum { SP_DIR_SENDRECV = 0, SP_DIR_SENDONLY, SP_DIR_RECVONLY, SP_DIR_INACTIVE };

#define SP_SDES_KEYING 30   /* AES_CM_128_HMAC_SHA1_80: 16-byte key + 14-byte salt */

typedef struct {
    int  ok;
    char ip[64];       /* connection address (media level wins over session level) */
    int  port;         /* 0 = stream rejected */
    int  pts[24];      /* payload types in preference order */
    int  npts;
    int  dtmf_pt;      /* telephone-event/8000, -1 if absent */
    int  dir;          /* as written by the sender of this SDP */
    int  ptime;
    int  savp;         /* m= profile was RTP/SAVP (SRTP) */
    int  have_crypto;  /* a usable a=crypto (our suite) was present */
    int  crypto_tag;   /* its tag */
    uint8_t crypto_key[SP_SDES_KEYING];
} sp_sdp;

int  sp_sdp_parse(const char *body, size_t len, sp_sdp *out);
/* first of our supported payloads (PCMU 0, PCMA 8) present in the remote list, -1 if none */
int  sp_sdp_choose(const sp_sdp *remote);
/* answer direction for a remote direction */
int  sp_sdp_answer_dir(int remote_dir, int local_hold);
/* srtp_key != NULL writes an RTP/SAVP stream with a=crypto:<crypto_tag> inline:<key>. */
void sp_sdp_build(char *out, size_t n, const char *ip, int port, uint32_t sess_id,
                  uint32_t ver, const int *pts, int npts, int dtmf_pt, int dir,
                  const uint8_t *srtp_key, int crypto_tag);
const char *sp_sdp_dir_name(int dir);

#endif

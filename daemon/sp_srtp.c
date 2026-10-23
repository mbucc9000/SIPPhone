#include "sp_srtp.h"
#include "sp_sha1.h"

#include <string.h>

/* --- base64 (standard alphabet, used only for the SDES inline key) --- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void sp_srtp_keying_to_b64(const uint8_t *in, char out[41])
{
    int o = 0;
    for (int i = 0; i < SP_SRTP_KEYING; i += 3) {
        int n = SP_SRTP_KEYING - i;
        uint32_t v = (uint32_t)in[i] << 16;
        if (n > 1) v |= (uint32_t)in[i + 1] << 8;
        if (n > 2) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = n > 1 ? B64[(v >> 6) & 63] : '=';
        out[o++] = n > 2 ? B64[v & 63] : '=';
    }
    out[o] = 0;   /* 30 bytes -> 40 chars, no padding */
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int sp_srtp_keying_from_b64(const char *b64, uint8_t out[SP_SRTP_KEYING])
{
    uint8_t buf[48];
    int nb = 0;
    uint32_t v = 0;
    int bits = 0;
    for (const char *p = b64; *p && *p != ';' && *p != '|'; p++) {
        if (*p == '=' || *p == ' ')
            break;
        int d = b64val(*p);
        if (d < 0)
            return -1;
        v = (v << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (nb < (int)sizeof buf)
                buf[nb++] = (uint8_t)(v >> bits);
        }
    }
    if (nb < SP_SRTP_KEYING)
        return -1;
    memcpy(out, buf, SP_SRTP_KEYING);
    return 0;
}

/* --- RFC 3711 key derivation (rate 0) --- */

static void kdf(const sp_aes *master, const uint8_t salt[SP_SRTP_MASTER_SALT],
                uint8_t label, uint8_t *out, int outlen)
{
    uint8_t ctr[16];
    memcpy(ctr, salt, SP_SRTP_MASTER_SALT);
    ctr[14] = ctr[15] = 0;
    ctr[7] ^= label;          /* key_id = label || 0 (rate 0) XOR salt */
    memset(out, 0, outlen);
    sp_aes_ctr_xor(master, ctr, out, outlen);
}

void sp_srtp_init(sp_srtp *s, const uint8_t keying[SP_SRTP_KEYING])
{
    memset(s, 0, sizeof *s);
    sp_aes master;
    sp_aes128_init(&master, keying);
    const uint8_t *msalt = keying + SP_SRTP_MASTER_KEY;

    uint8_t ekey[16];
    kdf(&master, msalt, 0x00, ekey, 16);          /* session encryption key */
    sp_aes128_init(&s->enc, ekey);
    kdf(&master, msalt, 0x02, s->salt, SP_SRTP_MASTER_SALT);  /* session salt */
    kdf(&master, msalt, 0x01, s->auth, 20);       /* session auth key */
}

/* AES-CM per-packet IV: salt*2^16 XOR SSRC*2^64 XOR (ROC||SEQ)*2^16 */
static void packet_iv(const sp_srtp *s, uint32_t ssrc, uint32_t roc, uint16_t seq, uint8_t iv[16])
{
    memcpy(iv, s->salt, SP_SRTP_MASTER_SALT);
    iv[14] = iv[15] = 0;
    iv[4] ^= (uint8_t)(ssrc >> 24);
    iv[5] ^= (uint8_t)(ssrc >> 16);
    iv[6] ^= (uint8_t)(ssrc >> 8);
    iv[7] ^= (uint8_t)ssrc;
    iv[8] ^= (uint8_t)(roc >> 24);
    iv[9] ^= (uint8_t)(roc >> 16);
    iv[10] ^= (uint8_t)(roc >> 8);
    iv[11] ^= (uint8_t)roc;
    iv[12] ^= (uint8_t)(seq >> 8);
    iv[13] ^= (uint8_t)seq;
}

static int rtp_hdr_len(const uint8_t *pkt, int len)
{
    if (len < 12 || (pkt[0] >> 6) != 2)
        return -1;
    int cc = pkt[0] & 0x0f;
    int hl = 12 + cc * 4;
    if (pkt[0] & 0x10) {                 /* extension */
        if (len < hl + 4)
            return -1;
        hl += 4 + ((pkt[hl + 2] << 8) | pkt[hl + 3]) * 4;
    }
    return len >= hl ? hl : -1;
}

static void auth_tag(const sp_srtp *s, const uint8_t *pkt, int len, uint32_t roc, uint8_t tag[SP_SRTP_TAG])
{
    /* HMAC over the packet (header+encrypted payload) followed by the ROC */
    uint8_t roc_be[4] = { (uint8_t)(roc >> 24), (uint8_t)(roc >> 16), (uint8_t)(roc >> 8), (uint8_t)roc };
    sp_sha1_ctx c;
    uint8_t k[64], ipad[64], opad[64], inner[20], mac[20];
    memset(k, 0, sizeof k);
    memcpy(k, s->auth, 20);
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sp_sha1_init(&c);
    sp_sha1_update(&c, ipad, 64);
    sp_sha1_update(&c, pkt, (size_t)len);
    sp_sha1_update(&c, roc_be, 4);
    sp_sha1_final(&c, inner);
    sp_sha1_init(&c);
    sp_sha1_update(&c, opad, 64);
    sp_sha1_update(&c, inner, 20);
    sp_sha1_final(&c, mac);
    memcpy(tag, mac, SP_SRTP_TAG);
}

int sp_srtp_protect(sp_srtp *s, uint8_t *pkt, int len, int cap)
{
    int hl = rtp_hdr_len(pkt, len);
    if (hl < 0 || len + SP_SRTP_TAG > cap)
        return -1;
    uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
    uint32_t ssrc = ((uint32_t)pkt[8] << 24) | ((uint32_t)pkt[9] << 16) |
                    ((uint32_t)pkt[10] << 8) | pkt[11];
    /* our own monotonic sender: bump ROC when the seq wraps 65535 -> 0
       (forward step whose 16-bit value went down) */
    if (s->seen && seq < s->last_seq && (uint16_t)(seq - s->last_seq) < 0x8000)
        s->roc++;
    s->last_seq = seq;
    s->seen = 1;
    uint32_t roc = s->roc;

    uint8_t iv[16];
    packet_iv(s, ssrc, roc, seq, iv);
    sp_aes_ctr_xor(&s->enc, iv, pkt + hl, (size_t)(len - hl));
    auth_tag(s, pkt, len, roc, pkt + len);
    return len + SP_SRTP_TAG;
}

/* Guess the ROC for a received seq (RFC 3711 3.3.1): pick the rollover that puts
   the packet closest to the highest index we have authenticated. */
static uint32_t guess_roc(const sp_srtp *s, uint16_t seq)
{
    if (!s->have_high)
        return s->roc;
    int sl = s->high_seq, sq = seq;    /* signed compares, RFC 3711 3.3.1 */
    if (sl < 32768) {
        if (sq - sl > 32768 && s->high_roc > 0)
            return s->high_roc - 1;
    } else {
        if (sl - sq > 32768)
            return s->high_roc + 1;
    }
    return s->high_roc;
}

static int replay_check(sp_srtp *s, uint32_t roc, uint16_t seq)
{
    uint64_t idx = ((uint64_t)roc << 16) | seq;
    uint64_t high = ((uint64_t)s->high_roc << 16) | s->high_seq;
    if (!s->have_high)
        return 1;
    if (idx > high)
        return 1;
    uint64_t d = high - idx;
    if (d >= 64)
        return 0;                 /* too old */
    return (s->replay & (1ull << d)) ? 0 : 1;
}

static void replay_update(sp_srtp *s, uint32_t roc, uint16_t seq)
{
    uint64_t idx = ((uint64_t)roc << 16) | seq;
    uint64_t high = ((uint64_t)s->high_roc << 16) | s->high_seq;
    if (!s->have_high || idx > high) {
        uint64_t shift = s->have_high ? idx - high : 0;
        s->replay = shift >= 64 ? 0 : (s->replay << shift);
        s->replay |= 1;           /* the new high is seen */
        s->high_roc = roc;
        s->high_seq = seq;
        s->have_high = 1;
        s->roc = roc;
    } else {
        uint64_t d = high - idx;
        if (d < 64)
            s->replay |= (1ull << d);
    }
}

int sp_srtp_unprotect(sp_srtp *s, uint8_t *pkt, int len)
{
    if (len < SP_SRTP_TAG)
        return -1;
    int plen = len - SP_SRTP_TAG;
    int hl = rtp_hdr_len(pkt, plen);
    if (hl < 0)
        return -1;
    uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
    uint32_t ssrc = ((uint32_t)pkt[8] << 24) | ((uint32_t)pkt[9] << 16) |
                    ((uint32_t)pkt[10] << 8) | pkt[11];
    uint32_t roc = guess_roc(s, seq);
    if (!replay_check(s, roc, seq))
        return -1;

    uint8_t want[SP_SRTP_TAG];
    auth_tag(s, pkt, plen, roc, want);
    uint8_t diff = 0;
    for (int i = 0; i < SP_SRTP_TAG; i++)      /* constant-time compare */
        diff |= want[i] ^ pkt[plen + i];
    if (diff)
        return -1;

    uint8_t iv[16];
    packet_iv(s, ssrc, roc, seq, iv);
    sp_aes_ctr_xor(&s->enc, iv, pkt + hl, (size_t)(plen - hl));
    replay_update(s, roc, seq);
    return plen;
}

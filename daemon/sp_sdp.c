#include "sp_sdp.h"
#include "sp_srtp.h"
#include "sp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *sp_sdp_dir_name(int dir)
{
    switch (dir) {
    case SP_DIR_SENDONLY: return "sendonly";
    case SP_DIR_RECVONLY: return "recvonly";
    case SP_DIR_INACTIVE: return "inactive";
    default: return "sendrecv";
    }
}

static int parse_c(const char *v, char *ip, size_t n)
{
    /* c=IN IP4 1.2.3.4 */
    char nt[8], at[8], addr[64];
    if (sscanf(v, "%7s %7s %63s", nt, at, addr) != 3)
        return -1;
    if (strcmp(nt, "IN") != 0 || strcmp(at, "IP4") != 0)
        return -1;
    char *slash = strchr(addr, '/');
    if (slash)
        *slash = 0;
    sp_strlcpy(ip, addr, n);
    return 0;
}

int sp_sdp_parse(const char *body, size_t len, sp_sdp *o)
{
    memset(o, 0, sizeof *o);
    o->dtmf_pt = -1;
    o->ptime = 20;
    char sess_ip[64] = "", media_ip[64] = "";
    int in_audio = 0, seen_audio = 0;
    int sess_dir = SP_DIR_SENDRECV, media_dir = -1;

    const char *p = body, *end = body + len;
    while (p < end) {
        const char *e = memchr(p, '\n', (size_t)(end - p));
        if (!e)
            e = end;
        size_t l = (size_t)(e - p);
        if (l && p[l - 1] == '\r')
            l--;
        char line[512];
        if (l >= sizeof line)
            l = sizeof line - 1;
        memcpy(line, p, l);
        line[l] = 0;
        p = e + 1;
        if (l < 2 || line[1] != '=')
            continue;
        char t = line[0];
        const char *v = line + 2;

        if (t == 'm') {
            in_audio = 0;
            if (strncmp(v, "audio ", 6) == 0 && !seen_audio) {
                seen_audio = in_audio = 1;
                const char *q = v + 6;
                o->port = atoi(q);
                q = strchr(q, ' ');          /* -> proto */
                if (q && strncmp(q + 1, "RTP/SAVP", 8) == 0)
                    o->savp = 1;
                if (q)
                    q = strchr(q + 1, ' ');  /* fmt list */
                while (q && *q) {
                    while (*q == ' ')
                        q++;
                    if (!*q)
                        break;
                    if (o->npts < (int)(sizeof o->pts / sizeof o->pts[0]))
                        o->pts[o->npts++] = atoi(q);
                    q = strchr(q, ' ');
                }
            }
        } else if (t == 'c') {
            if (!seen_audio)
                parse_c(v, sess_ip, sizeof sess_ip);
            else if (in_audio)
                parse_c(v, media_ip, sizeof media_ip);
        } else if (t == 'a') {
            int d = -1;
            if (strcmp(v, "sendrecv") == 0) d = SP_DIR_SENDRECV;
            else if (strcmp(v, "sendonly") == 0) d = SP_DIR_SENDONLY;
            else if (strcmp(v, "recvonly") == 0) d = SP_DIR_RECVONLY;
            else if (strcmp(v, "inactive") == 0) d = SP_DIR_INACTIVE;
            if (d >= 0) {
                if (in_audio)
                    media_dir = d;
                else if (!seen_audio)
                    sess_dir = d;
            } else if (in_audio && strncmp(v, "rtpmap:", 7) == 0) {
                int pt = atoi(v + 7);
                const char *nm = strchr(v, ' ');
                if (nm && sp_strncaseeq(nm + 1, "telephone-event/8000", 20))
                    o->dtmf_pt = pt;
            } else if (in_audio && strncmp(v, "ptime:", 6) == 0) {
                o->ptime = atoi(v + 6);
            } else if (in_audio && strncmp(v, "crypto:", 7) == 0 && !o->have_crypto) {
                /* a=crypto:<tag> AES_CM_128_HMAC_SHA1_80 inline:<b64>[|...] [params] */
                const char *q = v + 7;
                int tag = atoi(q);
                const char *suite = strchr(q, ' ');
                if (tag > 0 && suite && sp_strncaseeq(suite + 1, "AES_CM_128_HMAC_SHA1_80", 23)) {
                    const char *inl = strstr(suite, "inline:");
                    uint8_t key[SP_SDES_KEYING];
                    if (inl && sp_srtp_keying_from_b64(inl + 7, key) == 0) {
                        memcpy(o->crypto_key, key, SP_SDES_KEYING);
                        o->crypto_tag = tag;
                        o->have_crypto = 1;
                    }
                }
            }
        }
    }
    if (!seen_audio)
        return -1;
    sp_strlcpy(o->ip, media_ip[0] ? media_ip : sess_ip, sizeof o->ip);
    o->dir = media_dir >= 0 ? media_dir : sess_dir;
    if (strcmp(o->ip, "0.0.0.0") == 0 && o->dir == SP_DIR_SENDRECV)
        o->dir = SP_DIR_INACTIVE;   /* old-style hold (RFC 2543) */
    o->ok = o->ip[0] != 0;
    return o->ok ? 0 : -1;
}

int sp_sdp_choose(const sp_sdp *r)
{
    for (int i = 0; i < r->npts; i++)
        if (r->pts[i] == 0 || r->pts[i] == 8)
            return r->pts[i];
    return -1;
}

int sp_sdp_answer_dir(int remote_dir, int local_hold)
{
    int d;
    switch (remote_dir) {
    case SP_DIR_SENDONLY: d = SP_DIR_RECVONLY; break;
    case SP_DIR_RECVONLY: d = SP_DIR_SENDONLY; break;
    case SP_DIR_INACTIVE: d = SP_DIR_INACTIVE; break;
    default: d = SP_DIR_SENDRECV; break;
    }
    if (local_hold) {
        if (d == SP_DIR_SENDRECV) d = SP_DIR_SENDONLY;
        else if (d == SP_DIR_RECVONLY) d = SP_DIR_INACTIVE;
    }
    return d;
}

void sp_sdp_build(char *out, size_t n, const char *ip, int port, uint32_t sess_id,
                  uint32_t ver, const int *pts, int npts, int dtmf_pt, int dir,
                  const uint8_t *srtp_key, int crypto_tag)
{
    sp_buf b;
    sp_buf_init(&b);
    sp_buf_printf(&b, "v=0\r\no=- %u %u IN IP4 %s\r\ns=SIPPhone\r\nc=IN IP4 %s\r\nt=0 0\r\n",
                  sess_id, ver, ip, ip);
    sp_buf_printf(&b, "m=audio %d %s", port, srtp_key ? "RTP/SAVP" : "RTP/AVP");
    for (int i = 0; i < npts; i++)
        sp_buf_printf(&b, " %d", pts[i]);
    if (dtmf_pt >= 0)
        sp_buf_printf(&b, " %d", dtmf_pt);
    sp_buf_puts(&b, "\r\n");
    if (srtp_key) {
        char kb[41];
        sp_srtp_keying_to_b64(srtp_key, kb);
        sp_buf_printf(&b, "a=crypto:%d AES_CM_128_HMAC_SHA1_80 inline:%s\r\n",
                      crypto_tag > 0 ? crypto_tag : 1, kb);
    }
    for (int i = 0; i < npts; i++) {
        if (pts[i] == 0)
            sp_buf_puts(&b, "a=rtpmap:0 PCMU/8000\r\n");
        else if (pts[i] == 8)
            sp_buf_puts(&b, "a=rtpmap:8 PCMA/8000\r\n");
    }
    if (dtmf_pt >= 0)
        sp_buf_printf(&b, "a=rtpmap:%d telephone-event/8000\r\na=fmtp:%d 0-16\r\n", dtmf_pt, dtmf_pt);
    sp_buf_printf(&b, "a=ptime:20\r\na=%s\r\n", sp_sdp_dir_name(dir));
    sp_strlcpy(out, b.s ? b.s : "", n);
    sp_buf_free(&b);
}

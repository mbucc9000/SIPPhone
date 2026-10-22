#include "sp_rtp.h"
#include "sp_util.h"

#include <string.h>

/* ------------------------------------------------------------ G.711 */

#define ULAW_BIAS 0x84
#define ULAW_CLIP 32635

uint8_t sp_ulaw_enc(int16_t pcm)
{
    int p = pcm;                     /* widen before negating (-32768 overflows int16) */
    int sign = (p >> 8) & 0x80;
    if (sign)
        p = -p;
    if (p > ULAW_CLIP)
        p = ULAW_CLIP;
    p += ULAW_BIAS;
    int exp = 7;
    for (int m = 0x4000; (p & m) == 0 && exp > 0; m >>= 1)
        exp--;
    int mant = (p >> (exp + 3)) & 0x0f;
    return (uint8_t)~(sign | (exp << 4) | mant);
}

int16_t sp_ulaw_dec(uint8_t u)
{
    u = (uint8_t)~u;
    int sign = u & 0x80;
    int exp = (u >> 4) & 0x07;
    int mant = u & 0x0f;
    int mag = ((mant << 3) + ULAW_BIAS) << exp;
    mag -= ULAW_BIAS;
    return (int16_t)(sign ? -mag : mag);
}

uint8_t sp_alaw_enc(int16_t pcm)
{
    int p = pcm;                      /* widen before negating */
    int sign = (~p >> 8) & 0x80;      /* A-law: positive has sign bit set */
    int mag = sign ? p : -p;
    if (mag > 32767)
        mag = 32767;
    uint8_t a;
    if (mag < 256) {
        a = (uint8_t)(mag >> 4);
    } else {
        int exp = 7;
        for (int m = 0x4000; (mag & m) == 0 && exp > 1; m >>= 1)
            exp--;
        int mant = (mag >> (exp + 3)) & 0x0f;
        a = (uint8_t)((exp << 4) | mant);
    }
    return a ^ (uint8_t)(sign ^ 0x55);
}

int16_t sp_alaw_dec(uint8_t a)
{
    a ^= 0x55;
    int sign = a & 0x80;
    int exp = (a >> 4) & 0x07;
    int mant = a & 0x0f;
    int mag;
    if (exp == 0)
        mag = (mant << 4) + 8;
    else
        mag = ((mant << 4) + 0x108) << (exp - 1);
    return (int16_t)(sign ? mag : -mag);
}

static void enc_frame(int pt, const int16_t *pcm, uint8_t *out)
{
    if (pt == SP_PT_PCMA)
        for (int i = 0; i < SP_SAMPLES; i++)
            out[i] = sp_alaw_enc(pcm[i]);
    else
        for (int i = 0; i < SP_SAMPLES; i++)
            out[i] = sp_ulaw_enc(pcm[i]);
}

static int16_t dec_sample(int pt, uint8_t b)
{
    return pt == SP_PT_PCMA ? sp_alaw_dec(b) : sp_ulaw_dec(b);
}

/* ------------------------------------------------------------ RTP */

void sp_rtp_init(sp_rtp *r, int pt, int dtmf_pt)
{
    memset(r, 0, sizeof *r);
    r->pt = (pt == SP_PT_PCMA) ? SP_PT_PCMA : SP_PT_PCMU;
    r->dtmf_pt = dtmf_pt;
    r->ssrc = sp_rand32();
    r->seq = (uint16_t)sp_rand32();
    r->ts = sp_rand32();
    r->sending = r->recving = 1;
    r->jb_min = 2;           /* 40 ms nominal on a clean network */
    r->jb_target = 3;        /* start a little deeper: LTE delivers in bursts */
}

void sp_rtp_set_dir(sp_rtp *r, int sending, int recving)
{
    r->sending = sending;
    r->recving = recving;
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int hdr(sp_rtp *r, uint8_t *out, int pt, int marker, uint32_t ts)
{
    out[0] = 0x80;
    out[1] = (uint8_t)((marker ? 0x80 : 0) | (pt & 0x7f));
    wr16(out + 2, r->seq);
    wr32(out + 4, ts);
    wr32(out + 8, r->ssrc);
    r->seq++;
    return 12;
}

/* RFC 4733 telephone-event digit map */
static int dtmf_code(char d)
{
    if (d >= '0' && d <= '9')
        return d - '0';
    if (d == '*')
        return 10;
    if (d == '#')
        return 11;
    if (d >= 'A' && d <= 'D')
        return 12 + (d - 'A');
    if (d >= 'a' && d <= 'd')
        return 12 + (d - 'a');
    return -1;
}

void sp_rtp_send_dtmf(sp_rtp *r, char digit)
{
    int c = dtmf_code(digit);
    if (c < 0 || r->dtmf_pt < 0 || r->dtmf_active)
        return;
    r->dtmf_active = 1;
    r->dtmf_event = c;
    r->dtmf_ms = 0;
    r->dtmf_start_ts = r->ts;
    r->dtmf_end_sent = 0;
}

int sp_rtp_build(sp_rtp *r, const int16_t *pcm, uint8_t *out, size_t n)
{
    if (!r->sending)
        return 0;
    if (r->dtmf_active && r->dtmf_pt >= 0) {
        if (n < 16)
            return 0;
        int first = r->dtmf_ms == 0;
        r->dtmf_ms += SP_PTIME_MS;
        int dur = (r->dtmf_ms) * SP_CLOCK / 1000;        /* samples since start */
        int end = r->dtmf_ms >= 120;
        int len = hdr(r, out, r->dtmf_pt, first, r->dtmf_start_ts);
        out[len++] = (uint8_t)r->dtmf_event;
        out[len++] = (uint8_t)((end ? 0x80 : 0) | 10);   /* E flag, volume 10 */
        wr16(out + len, (uint16_t)dur);
        len += 2;
        r->ts += SP_SAMPLES;
        if (end) {
            if (!r->dtmf_end_sent) {
                r->dtmf_end_sent = 1;   /* repeat end packet twice */
            } else {
                r->dtmf_active = 0;
            }
        }
        r->tx_pkts++;
        return len;
    }
    if (n < 12 + SP_SAMPLES)
        return 0;
    int len = hdr(r, out, r->pt, r->tx_started == 0, r->ts);
    enc_frame(r->pt, pcm, out + len);
    len += SP_SAMPLES;
    r->ts += SP_SAMPLES;
    r->tx_started = 1;      /* never touch got_first here: that would skip the RX timeline init */
    r->tx_pkts++;
    return len;
}

/* ------------------------------------------------------------ jitter buffer */

#define JB_MAX_TARGET   8    /* adaptive delay ceiling: 160 ms */
#define JB_DECAY        750  /* 15 s of good audio since the target last grew: shrink it a frame */
#define JB_SOFT_HOLD    50   /* 1 s window: if a whole spare frame sat unused all window, shed it */
#define JB_LATE_WINDOW  ((JB_MAX_TARGET + 2) * SP_SAMPLES)   /* how late still counts as jitter */
#define JB_HARD_EXTRA   15   /* queue this far past the target (a stall's backlog): skip to the target */
#define JB_LATE_RESYNC  5    /* consecutive wholly-late packets = the sender jumped back */
#define JB_MISS_RESYNC  25   /* 500 ms of concealment while packets still arrive */
#define JB_SSRC_SWITCH  3    /* consecutive packets from a new SSRC before it takes over */

/* Start a new playout timeline at `ts`: the first packet, or the sender jumped. */
static void rx_restart(sp_rtp *r, uint32_t ts, uint32_t ssrc)
{
    memset(r->jb_ok, 0, sizeof r->jb_ok);
    r->rx_ssrc = ssrc;
    r->play_ts = ts;
    r->rx_end_ts = ts;
    r->jb_primed = 0;
    r->late_run = 0;
    r->miss_run = 0;
    r->cand_count = 0;
    r->got_first = 1;
}

static void jb_grow(sp_rtp *r)
{
    if (r->jb_target < JB_MAX_TARGET)
        r->jb_target++;
    r->jb_clean = 0;
}

/* The target grows only on proof of jitter: a packet arriving for samples we
   already played as concealment. A plain hole (loss) or a sender pause (silence
   suppression, end of a prompt) never shows up late, so it never inflates the
   delay. Claimed slots are cleared so a duplicate can't count twice. */
static int claim_late(sp_rtp *r, uint32_t ts, int ns)
{
    int hit = 0;
    for (int i = 0; i < ns; i++) {
        uint32_t t = ts + (uint32_t)i;
        int32_t behind = (int32_t)(r->play_ts - t);
        if (behind <= 0)
            break;
        if (behind <= JB_LATE_WINDOW && r->jb_ok[t & SP_JB_MASK] == 2) {
            r->jb_ok[t & SP_JB_MASK] = 0;
            hit = 1;
        }
    }
    return hit;
}

int sp_rtp_recv(sp_rtp *r, const uint8_t *pkt, size_t n)
{
    if (!r->recving || n < 12 || (pkt[0] >> 6) != 2)
        return -1;
    int cc = pkt[0] & 0x0f;
    int ext = pkt[0] & 0x10;
    int pt = pkt[1] & 0x7f;
    size_t off = 12 + (size_t)cc * 4;
    if (ext) {
        if (n < off + 4)
            return -1;
        off += 4 + (size_t)rd16(pkt + off + 2) * 4;
    }
    if (off > n)
        return -1;
    uint32_t ts = rd32(pkt + 4);
    uint32_t ssrc = rd32(pkt + 8);
    if (r->dtmf_pt >= 0 && pt == r->dtmf_pt)
        return 0;        /* inbound DTMF: accepted, not queued as audio */
    if (pt != r->pt)
        return -1;
    size_t payload = n - off;
    if (payload == 0 || payload > SP_MAX_PKT_SAMPLES)
        return -1;
    int ns = (int)payload;     /* G.711: one byte per sample */
    r->rx_pkts++;

    /* Senders do jump: Asterisk (VoIP.ms) re-bases the timestamps when its audio
       source changes, e.g. from the echo test's prompt to the echo itself. A
       timeline keyed to the old base would treat every later packet as missing,
       so restart it whenever the stream stops lining up with the playout point. */
    if (r->got_first && ssrc != r->rx_ssrc) {
        /* A stray stream (the last call's tail, a forked leg) must not grab the
           timeline packet by packet; a real source change sends steadily. */
        if (ssrc == r->cand_ssrc && r->cand_count > 0)
            r->cand_count++;
        else {
            r->cand_ssrc = ssrc;
            r->cand_count = 1;
        }
        if (r->cand_count < JB_SSRC_SWITCH) {
            r->rx_oop++;
            return 0;
        }
        rx_restart(r, ts, ssrc);           /* the new source is for real */
        r->rx_resync++;
    } else if (r->got_first) {
        r->cand_count = 0;                 /* the current source is still talking */
    }

    if (!r->got_first) {
        rx_restart(r, ts, ssrc);
    } else if (!r->jb_primed && (int32_t)(r->rx_end_ts - r->play_ts) <= 0) {
        if (claim_late(r, ts, ns))
            jb_grow(r);                    /* we ran dry because this was late: buffer deeper */
        rx_restart(r, ts, ssrc);           /* drained: start fresh on this packet's grid, don't replay the gap */
    } else {
        int32_t d = (int32_t)(ts - r->play_ts);
        int resync = 0;
        if (d < 0 && claim_late(r, ts, ns))
            jb_grow(r);
        if (d > SP_JB_LEN - ns) {
            resync = 1;                    /* too far ahead to buffer */
        } else if (d + ns <= 0) {          /* wholly behind the playout point */
            if (++r->late_run < JB_LATE_RESYNC) {
                r->rx_oop++;               /* a straggler or duplicate: drop it */
                return 0;
            }
            resync = 1;                    /* every packet is late: the sender jumped backwards */
        } else if (r->jb_primed && r->miss_run >= JB_MISS_RESYNC) {
            resync = 1;                    /* safety net: packets arrive but nothing plays */
        }
        if (resync) {
            rx_restart(r, ts, ssrc);
            r->rx_resync++;
        }
    }
    r->late_run = 0;

    for (int i = 0; i < ns; i++) {
        uint32_t t = ts + (uint32_t)i;
        if ((int32_t)(t - r->play_ts) < 0)
            continue;                      /* the part already played out */
        int idx = (int)(t & SP_JB_MASK);
        r->jb_pcm[idx] = dec_sample(r->pt, pkt[off + (size_t)i]);
        r->jb_ok[idx] = 1;
    }
    if ((int32_t)(ts + (uint32_t)ns - r->rx_end_ts) > 0)
        r->rx_end_ts = ts + (uint32_t)ns;
    return 0;
}

int sp_rtp_drop_backlog(sp_rtp *r)
{
    if (!r->jb_primed)
        return 0;
    int32_t depth = (int32_t)(r->rx_end_ts - r->play_ts);
    int32_t want = (r->jb_target + 1) * SP_SAMPLES;
    if (depth <= want)
        return 0;
    uint32_t to = r->rx_end_ts - (uint32_t)want;
    int dropped = 0;
    while (r->play_ts != to) {
        r->jb_ok[r->play_ts & SP_JB_MASK] = 0;
        r->play_ts++;
        dropped++;
    }
    r->jb_over = 0;
    r->rx_trim++;
    return dropped;
}

int sp_rtp_playout(sp_rtp *r, int16_t *pcm)
{
    int32_t depth = (int32_t)(r->rx_end_ts - r->play_ts);    /* samples queued ahead */
    if (!r->jb_primed) {
        if (!r->got_first || depth < (r->jb_target + 1) * SP_SAMPLES) {
            memset(pcm, 0, sizeof(int16_t) * SP_SAMPLES);
            return 0;
        }
        r->jb_primed = 1;
        r->miss_run = 0;
    }
    int want = (r->jb_target + 1) * SP_SAMPLES;
    uint32_t skip_to = r->play_ts;
    if (depth > want + JB_HARD_EXTRA * SP_SAMPLES) {
        skip_to = r->rx_end_ts - (uint32_t)want;     /* a stall's backlog: that audio is stale anyway */
        r->jb_over = 0;
    } else {
        /* Shed one frame per second while a whole spare frame sat unused for the
           entire window: the queue drifts back to the target without audible chunks. */
        if (r->jb_over == 0 || depth < r->jb_lo)
            r->jb_lo = depth;
        if (++r->jb_over >= JB_SOFT_HOLD) {
            if (r->jb_lo >= want + SP_SAMPLES)
                skip_to = r->play_ts + SP_SAMPLES;
            r->jb_over = 0;
        }
    }
    if (skip_to != r->play_ts) {
        while (r->play_ts != skip_to) {
            r->jb_ok[r->play_ts & SP_JB_MASK] = 0;
            r->play_ts++;
        }
        r->rx_trim++;
    }
    int got = 0;
    for (int i = 0; i < SP_SAMPLES; i++) {
        int idx = (int)((r->play_ts + (uint32_t)i) & SP_JB_MASK);
        if (r->jb_ok[idx] == 1) {
            pcm[i] = r->jb_pcm[idx];
            r->jb_ok[idx] = 0;
            got++;
        } else {
            pcm[i] = (int16_t)(r->last_pcm[i] * 3 / 4);   /* PLC: decayed repeat of the last frame */
            r->jb_ok[idx] = 2;             /* remember it was concealed (see claim_late) */
        }
    }
    memcpy(r->last_pcm, pcm, sizeof r->last_pcm);
    r->play_ts += SP_SAMPLES;
    int32_t left = (int32_t)(r->rx_end_ts - r->play_ts);
    if (got && left >= 0) {
        r->miss_run = 0;
        if (++r->jb_clean >= JB_DECAY && r->jb_target > r->jb_min) {
            r->jb_target--;                /* the network calmed down: give the latency back */
            r->jb_clean = 0;
        }
        return 1;
    }
    /* Nothing to play, or the frame ran past the newest sample (possible off the
       packet grid: a misaligned re-base, 10/30 ms packets). Both are underruns;
       left alone the second would clip the head of every following packet. */
    r->rx_lost++;
    r->miss_run++;
    if (left <= 0)
        r->jb_primed = 0;                  /* nothing queued: the next packet restarts on its own grid */
    return got ? 1 : 0;
}

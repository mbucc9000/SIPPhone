/* RTP/RTCP for one G.711 audio stream (RFC 3550) + a small jitter buffer.
   Sans-IO: sp_rtp_build() makes an outbound packet from 20 ms of PCM, and
   sp_rtp_recv() takes an inbound packet and queues decoded PCM for playback. */
#ifndef SP_RTP_H
#define SP_RTP_H

#include <stddef.h>
#include <stdint.h>

#define SP_PTIME_MS   20
#define SP_CLOCK      8000
#define SP_SAMPLES    (SP_CLOCK * SP_PTIME_MS / 1000)   /* 160 */
#define SP_PT_PCMU    0
#define SP_PT_PCMA    8

#define SP_JB_LEN     8192          /* 1.024 s of samples; a power of two so ts & mask survives wrap */
#define SP_JB_MASK    (SP_JB_LEN - 1)
#define SP_MAX_PKT_SAMPLES (SP_SAMPLES * 6)   /* accept up to 120 ms per packet */

/* G.711 (companding is pure-C and host-testable) */
uint8_t sp_ulaw_enc(int16_t pcm);
int16_t sp_ulaw_dec(uint8_t u);
uint8_t sp_alaw_enc(int16_t pcm);
int16_t sp_alaw_dec(uint8_t a);

typedef struct {
    int      pt;            /* SP_PT_PCMU / SP_PT_PCMA */
    int      dtmf_pt;       /* -1 if peer offered none */
    uint32_t ssrc;
    uint16_t seq;
    uint32_t ts;
    int      sending;       /* our direction allows TX */
    int      recving;       /* our direction allows RX */

    /* jitter buffer: a ring of samples indexed by RTP timestamp (ts & SP_JB_MASK),
       so any packet size or timestamp alignment lands in the right place. The
       timeline resyncs when the sender jumps (new SSRC, timestamp jump, restart). */
    int16_t  jb_pcm[SP_JB_LEN];
    uint8_t  jb_ok[SP_JB_LEN];   /* 0 empty, 1 audio, 2 played as concealment (a late packet proves jitter) */
    int      jb_target;     /* frames of nominal delay; grows on underruns, decays when clean */
    int      jb_min;        /* floor for jb_target */
    int      jb_clean;      /* good playouts since the target last grew */
    int      jb_over;       /* playouts into the current soft-trim window */
    int32_t  jb_lo;         /* lowest pre-playout queue depth seen in that window */
    int      jb_primed;
    uint32_t play_ts;       /* timestamp we will hand out next */
    uint32_t rx_end_ts;     /* just past the newest sample received */
    uint32_t rx_ssrc;
    uint32_t cand_ssrc;     /* a different SSRC we have seen; adopted after a few in a row */
    int      cand_count;
    int      late_run;      /* consecutive packets entirely behind the playout point */
    int      miss_run;      /* consecutive fully concealed frames while primed */
    int      got_first;     /* RX: playout timeline initialised from the first packet */
    int      tx_started;    /* TX: first packet sent (RTP marker bit) */
    int16_t  last_pcm[SP_SAMPLES];   /* for PLC on a gap */

    /* outbound DTMF (RFC 4733) in progress */
    int      dtmf_active;
    int      dtmf_event;
    int      dtmf_ms;
    uint32_t dtmf_start_ts;
    int      dtmf_end_sent;

    /* stats */
    uint32_t tx_pkts, rx_pkts, rx_lost, rx_oop, rx_resync, rx_trim;
} sp_rtp;

void sp_rtp_init(sp_rtp *r, int pt, int dtmf_pt);
void sp_rtp_set_dir(sp_rtp *r, int sending, int recving);

/* Encode one 20 ms PCM frame (SP_SAMPLES samples) into an RTP packet.
   Returns packet length, or 0 when nothing should be sent (e.g. recvonly). */
int sp_rtp_build(sp_rtp *r, const int16_t *pcm, uint8_t *out, size_t n);

/* Queue a received packet. Returns 0 ok, -1 ignored (wrong pt / malformed). */
int sp_rtp_recv(sp_rtp *r, const uint8_t *pkt, size_t n);

/* Pull the next 20 ms of PCM for the speaker (concealment on underrun).
   Returns 1 if real audio, 0 if it synthesised silence/PLC. */
int sp_rtp_playout(sp_rtp *r, int16_t *pcm);

/* Skip queued audio down to the current target delay (after the audio unit was
   rebuilt or stalled, whatever piled up meanwhile is stale). Returns samples dropped. */
int sp_rtp_drop_backlog(sp_rtp *r);

/* Start sending a DTMF digit ('0'-'9','*','#','A'-'D'); it spans several
   outbound packets built by sp_rtp_build. */
void sp_rtp_send_dtmf(sp_rtp *r, char digit);

#endif

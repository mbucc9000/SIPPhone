/* Host tests for the G.711 codec, RTP framing, jitter buffer and DTMF. */
#include "sp_rtp.h"
#include "sp_util.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

static int g_fail, g_pass;
#define CHECK(c, ...) do { if (c) { g_pass++; } else { \
    g_fail++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void t_codec(void)
{
    printf("[G.711 round-trip]\n");
    /* companding is lossy but monotonic and bounded; check error stays small */
    double worst_u = 0, worst_a = 0;
    for (int s = -32768; s < 32768; s += 7) {
        int16_t x = (int16_t)s;
        int16_t ru = sp_ulaw_dec(sp_ulaw_enc(x));
        int16_t ra = sp_alaw_dec(sp_alaw_enc(x));
        double eu = fabs((double)ru - x) / (fabs((double)x) + 256);
        double ea = fabs((double)ra - x) / (fabs((double)x) + 256);
        if (eu > worst_u) worst_u = eu;
        if (ea > worst_a) worst_a = ea;
    }
    CHECK(worst_u < 0.08, "ulaw relative error bounded (%.3f)", worst_u);
    CHECK(worst_a < 0.08, "alaw relative error bounded (%.3f)", worst_a);
    /* known test vectors */
    CHECK(sp_ulaw_enc(0) == 0xff, "ulaw(0)=0xFF got %02x", sp_ulaw_enc(0));
    CHECK(sp_alaw_enc(0) == 0xd5, "alaw(0)=0xD5 got %02x", sp_alaw_enc(0));
    /* a loud sine survives with recognisable shape */
    double maxerr = 0;
    for (int i = 0; i < 160; i++) {
        int16_t x = (int16_t)(20000 * sin(i * 0.3));
        int16_t r = sp_ulaw_dec(sp_ulaw_enc(x));
        double e = fabs((double)r - x) / 20000.0;
        if (e > maxerr) maxerr = e;
    }
    CHECK(maxerr < 0.05, "sine preserved within 5%% (%.3f)", maxerr);
}

static void fill_tone(int16_t *pcm, int base)
{
    for (int i = 0; i < SP_SAMPLES; i++)
        pcm[i] = (int16_t)(1000 + base + i);
}

static void t_rtp_frame(void)
{
    printf("[RTP build/parse]\n");
    sp_rtp tx, rx;
    sp_rtp_init(&tx, SP_PT_PCMU, 101);
    sp_rtp_init(&rx, SP_PT_PCMU, 101);
    int16_t in[SP_SAMPLES], out[SP_SAMPLES];
    fill_tone(in, 0);
    uint8_t pkt[256];
    int n = sp_rtp_build(&tx, in, pkt, sizeof pkt);
    CHECK(n == 12 + SP_SAMPLES, "packet is header + 160 bytes, got %d", n);
    CHECK((pkt[0] >> 6) == 2, "version 2");
    CHECK((pkt[1] & 0x80) != 0, "marker set on first packet");
    CHECK((pkt[1] & 0x7f) == SP_PT_PCMU, "payload type PCMU");
    int n2 = sp_rtp_build(&tx, in, pkt, sizeof pkt);
    CHECK(n2 == n && (pkt[1] & 0x80) == 0, "marker clear on 2nd packet");
    /* feed into rx and play out (needs jb_target frames first) */
    CHECK(sp_rtp_recv(&rx, pkt, n2) == 0, "recv accepts packet");
    sp_rtp_build(&tx, in, pkt, sizeof pkt);
    sp_rtp_recv(&rx, pkt, 12 + SP_SAMPLES);
    sp_rtp_build(&tx, in, pkt, sizeof pkt);
    sp_rtp_recv(&rx, pkt, 12 + SP_SAMPLES);
    sp_rtp_build(&tx, in, pkt, sizeof pkt);
    sp_rtp_recv(&rx, pkt, 12 + SP_SAMPLES);
    int got_audio = 0;
    for (int i = 0; i < 4; i++)
        got_audio |= sp_rtp_playout(&rx, out);
    CHECK(got_audio, "jitter buffer yields real audio after priming");
    CHECK(rx.rx_pkts >= 3, "counted received packets");
}

static void t_jitter_reorder(void)
{
    printf("[jitter buffer reorders]\n");
    sp_rtp tx, rx;
    sp_rtp_init(&tx, SP_PT_PCMU, -1);
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkts[6][256];
    int lens[6];
    int16_t in[SP_SAMPLES], out[SP_SAMPLES];
    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < SP_SAMPLES; j++)
            in[j] = (int16_t)(i * 1000 + j);   /* each frame uniquely valued */
        lens[i] = sp_rtp_build(&tx, in, pkts[i], 256);
    }
    /* deliver out of order: 0, 2, 1, 3, 5, 4 */
    int order[6] = { 0, 2, 1, 3, 5, 4 };
    for (int i = 0; i < 6; i++)
        sp_rtp_recv(&rx, pkts[order[i]], lens[order[i]]);
    /* play out: should emerge in timestamp order 0..5 (compare through the
       lossy codec, so expect the companded value rather than the exact PCM) */
    int ok = 1, reals = 0;
    for (int i = 0; i < 6; i++) {
        int real = sp_rtp_playout(&rx, out);
        if (real) {
            int16_t expect = sp_ulaw_dec(sp_ulaw_enc((int16_t)(i * 1000)));
            if (out[0] != expect)
                ok = 0;
            reals++;
        }
    }
    CHECK(ok && reals >= 5, "frames play back in order despite reordered arrival (%d real)", reals);
}

static void t_loss(void)
{
    printf("[packet loss concealment]\n");
    sp_rtp tx, rx;
    sp_rtp_init(&tx, SP_PT_PCMU, -1);
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[256];
    int16_t in[SP_SAMPLES], out[SP_SAMPLES];
    fill_tone(in, 500);
    /* send 4 frames but drop the 3rd before playout */
    for (int i = 0; i < 4; i++) {
        int n = sp_rtp_build(&tx, in, pkt, sizeof pkt);
        if (i != 2)
            sp_rtp_recv(&rx, pkt, n);
    }
    int reals = 0, conceals = 0;
    for (int i = 0; i < 4; i++) {
        if (sp_rtp_playout(&rx, out))
            reals++;
        else
            conceals++;
    }
    CHECK(conceals >= 1, "at least one frame concealed, got %d", conceals);
    CHECK(reals >= 2, "real frames still delivered around the gap, got %d", reals);
    CHECK(rx.rx_lost >= 1, "loss counter incremented");
}

static void t_dtmf(void)
{
    printf("[outbound DTMF / RFC 4733]\n");
    sp_rtp tx;
    sp_rtp_init(&tx, SP_PT_PCMU, 101);
    int16_t in[SP_SAMPLES];
    fill_tone(in, 0);
    sp_rtp_send_dtmf(&tx, '5');
    uint8_t pkt[256];
    int events = 0, end = 0, first = 0;
    for (int i = 0; i < 12 && tx.dtmf_active; i++) {
        int n = sp_rtp_build(&tx, in, pkt, sizeof pkt);
        if (n >= 16 && (pkt[1] & 0x7f) == 101) {
            events++;
            if (pkt[1] & 0x80)
                first++;
            if (pkt[12 + 1] & 0x80)
                end++;
            CHECK(pkt[12] == 5, "event payload is digit 5");
        }
    }
    CHECK(events >= 6, "DTMF spans ~120ms of packets, got %d", events);
    CHECK(first == 1, "exactly one marker (start) packet, got %d", first);
    CHECK(end >= 1, "end bit set on the final packet(s)");
    /* after the digit, audio resumes */
    int n = sp_rtp_build(&tx, in, pkt, sizeof pkt);
    CHECK(n == 12 + SP_SAMPLES, "audio resumes after DTMF, got %d", n);
}

static void t_recvonly(void)
{
    printf("[direction gating]\n");
    sp_rtp r;
    sp_rtp_init(&r, SP_PT_PCMU, -1);
    sp_rtp_set_dir(&r, 0, 1);   /* recvonly: do not transmit */
    int16_t in[SP_SAMPLES];
    uint8_t pkt[256];
    fill_tone(in, 0);
    CHECK(sp_rtp_build(&r, in, pkt, sizeof pkt) == 0, "recvonly suppresses TX");
    sp_rtp_set_dir(&r, 1, 0);   /* sendonly: drop inbound */
    sp_rtp tx;
    sp_rtp_init(&tx, SP_PT_PCMU, -1);
    int n = sp_rtp_build(&tx, in, pkt, sizeof pkt);
    CHECK(sp_rtp_recv(&r, pkt, n) == -1, "sendonly ignores inbound audio");
}


static void t_tx_first_then_rx(void)
{
    printf("[mic packet sent before any audio arrives still lets playout start]\n");
    sp_rtp tx, peer;
    sp_rtp_init(&tx, SP_PT_PCMU, -1);
    sp_rtp_init(&peer, SP_PT_PCMU, -1);
    int16_t in[SP_SAMPLES], out[SP_SAMPLES];
    fill_tone(in, 300);
    uint8_t pkt[256];
    sp_rtp_build(&tx, in, pkt, sizeof pkt);           /* we talk first */
    int reals = 0;
    for (int i = 0; i < 6; i++) {
        int n = sp_rtp_build(&peer, in, pkt, sizeof pkt);
        sp_rtp_recv(&tx, pkt, n);
        reals += sp_rtp_playout(&tx, out);
    }
    CHECK(reals >= 3, "far-end audio plays after we transmitted first (%d real frames)", reals);
}

/* ---- far-end stream discontinuities (what VoIP.ms's echo test actually does) ---- */

static int mk_pkt(uint8_t *out, uint32_t ssrc, uint16_t seq, uint32_t ts, int ns, int16_t val)
{
    out[0] = 0x80;
    out[1] = SP_PT_PCMU;
    out[2] = (uint8_t)(seq >> 8);
    out[3] = (uint8_t)seq;
    out[4] = (uint8_t)(ts >> 24);
    out[5] = (uint8_t)(ts >> 16);
    out[6] = (uint8_t)(ts >> 8);
    out[7] = (uint8_t)ts;
    out[8] = (uint8_t)(ssrc >> 24);
    out[9] = (uint8_t)(ssrc >> 16);
    out[10] = (uint8_t)(ssrc >> 8);
    out[11] = (uint8_t)ssrc;
    for (int i = 0; i < ns; i++)
        out[12 + i] = sp_ulaw_enc(val);
    return 12 + ns;
}

/* frames whose every sample is the companded `val` (no concealment mixed in) */
static int frame_is(const int16_t *pcm, int16_t val)
{
    int16_t want = sp_ulaw_dec(sp_ulaw_enc(val));
    for (int i = 0; i < SP_SAMPLES; i++)
        if (pcm[i] != want)
            return 0;
    return 1;
}

/* 100 frames from stream A, then 100 from stream B, delivered in real time (one
   packet per 20 ms playout tick). Returns how many of B's last 90 frames played
   as clean B audio. */
static int run_switch(uint32_t ssrc_a, uint32_t base_a, uint32_t ssrc_b, uint32_t base_b, sp_rtp *rx)
{
    sp_rtp_init(rx, SP_PT_PCMU, 101);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    int good = 0;
    for (int k = 0; k < 200; k++) {
        int n = k < 100 ? mk_pkt(pkt, ssrc_a, (uint16_t)k, base_a + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1000)
                        : mk_pkt(pkt, ssrc_b, (uint16_t)k, base_b + (uint32_t)(k - 100) * SP_SAMPLES, SP_SAMPLES, 3000);
        sp_rtp_recv(rx, pkt, (size_t)n);
        sp_rtp_playout(rx, out);
        if (k >= 110 && frame_is(out, 3000))
            good++;
    }
    return good;
}

static void t_stream_jumps(void)
{
    printf("[far end re-bases its stream mid-call]\n");
    sp_rtp rx;
    uint32_t a = 0x12345678;
    uint32_t next = a + 100 * SP_SAMPLES;      /* where A would have continued */
    int g;

    g = run_switch(0xAAAA, a, 0xAAAA, next + 77, &rx);
    CHECK(g == 90, "same SSRC, misaligned jump +77 samples (the 4443 echo case): %d/90 clean", g);
    g = run_switch(0xAAAA, a, 0xAAAA, next + 1000, &rx);
    CHECK(g == 90, "same SSRC, jump +1000 (inside the buffer): %d/90 clean", g);
    g = run_switch(0xAAAA, a, 0xAAAA, next + 987654, &rx);
    CHECK(g == 90 && rx.rx_resync >= 1, "same SSRC, jump far ahead: %d/90 clean, resync %u", g, rx.rx_resync);
    g = run_switch(0xAAAA, a, 0xAAAA, next - 5000, &rx);
    CHECK(g == 90, "same SSRC, jump back 5000: %d/90 clean", g);
    g = run_switch(0xAAAA, a, 0xAAAA, a - 1000000, &rx);
    CHECK(g == 90, "same SSRC, jump far back: %d/90 clean", g);
    g = run_switch(0xAAAA, a, 0xBBBB, 0x9E3779B9, &rx);
    CHECK(g == 90 && rx.rx_resync >= 1, "new SSRC + random base: %d/90 clean, resync %u", g, rx.rx_resync);
    g = run_switch(0xAAAA, a, 0xBBBB, next, &rx);
    CHECK(g == 90, "new SSRC, continuous timestamps: %d/90 clean", g);
    g = run_switch(0xAAAA, 0xFFFFFFFFu - 50 * SP_SAMPLES + 33, 0xAAAA, 0xFFFFFFFFu - 50 * SP_SAMPLES + 33 + 100 * SP_SAMPLES, &rx);
    CHECK(g == 90 && rx.rx_resync == 0 && rx.rx_lost <= 3,
          "timestamp wrap at 2^32 is seamless: %d/90 clean, resync %u, lost %u", g, rx.rx_resync, rx.rx_lost);
}

/* packets of `ns` samples delivered at their real-time rate; every frame after
   warm-up must be clean (no concealment seams) */
static int run_ptime(int ns)
{
    sp_rtp rx;
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[1024];
    int16_t out[SP_SAMPLES];
    uint32_t base = 4242, sent_to = 0;   /* samples delivered so far */
    int clean = 0, seq = 0;
    for (int tick = 0; tick < 150; tick++) {
        uint32_t now = (uint32_t)(tick + 1) * SP_SAMPLES;
        while (sent_to + (uint32_t)ns <= now) {
            int n = mk_pkt(pkt, 7, (uint16_t)seq++, base + sent_to, ns, 2000);
            sp_rtp_recv(&rx, pkt, (size_t)n);
            sent_to += (uint32_t)ns;
        }
        sp_rtp_playout(&rx, out);
        if (tick >= 30 && frame_is(out, 2000))
            clean++;
    }
    return clean;
}

static void t_ptime(void)
{
    printf("[other packet sizes]\n");
    int c;
    c = run_ptime(80);
    CHECK(c == 120, "10 ms packets play clean: %d/120", c);
    c = run_ptime(240);
    CHECK(c == 120, "30 ms packets play clean: %d/120", c);
    c = run_ptime(160);
    CHECK(c == 120, "20 ms packets play clean: %d/120", c);
}

static void t_stray_stream(void)
{
    printf("[a second stream interleaved (last call's tail) doesn't hijack playback]\n");
    sp_rtp rx;
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    int clean = 0;
    for (int k = 0; k < 120; k++) {
        int n = mk_pkt(pkt, 0xB0B0, (uint16_t)k, 9000 + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1800);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        if (k < 100) {                          /* old stream still trickling in, interleaved */
            n = mk_pkt(pkt, 0xAAAA, (uint16_t)(500 + k), 777777 + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, -1800);
            sp_rtp_recv(&rx, pkt, (size_t)n);
        }
        sp_rtp_playout(&rx, out);
        if (k >= 10 && frame_is(out, 1800))
            clean++;
    }
    CHECK(clean == 110, "current stream keeps playing: %d/110 clean, resync %u", clean, rx.rx_resync);
}

static void t_jump_back_deep_queue(void)
{
    printf("[backward jump while a deep queue is still playing]\n");
    sp_rtp rx;
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    uint32_t base = 50000;
    int k = 0;
    for (; k < 8; k++) {                        /* start with ~8 frames queued */
        int n = mk_pkt(pkt, 5, (uint16_t)k, base + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1000);
        sp_rtp_recv(&rx, pkt, (size_t)n);
    }
    for (; k < 60; k++) {
        int n = mk_pkt(pkt, 5, (uint16_t)k, base + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1000);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        sp_rtp_playout(&rx, out);
    }
    int clean = 0;
    for (int j = 0; j < 80; j++, k++) {         /* the sender restarts 3 s back */
        int n = mk_pkt(pkt, 5, (uint16_t)k, base - 24000 + (uint32_t)j * SP_SAMPLES, SP_SAMPLES, 2500);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        sp_rtp_playout(&rx, out);
        if (j >= 20 && frame_is(out, 2500))
            clean++;
    }
    CHECK(clean == 60 && rx.rx_resync >= 1, "recovers via the late-packet resync: %d/60 clean, resync %u",
          clean, rx.rx_resync);
}

static void t_burst_and_strays(void)
{
    printf("[stall + burst, duplicates, stray late packet]\n");
    sp_rtp rx;
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    uint32_t base = 777;
    int k = 0;
    for (; k < 50; k++) {                       /* steady */
        int n = mk_pkt(pkt, 9, (uint16_t)k, base + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1500);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        sp_rtp_playout(&rx, out);
    }
    for (int t = 0; t < 30; t++)                /* 600 ms network stall */
        sp_rtp_playout(&rx, out);
    for (; k < 80; k++) {                       /* the 30 delayed packets land at once */
        int n = mk_pkt(pkt, 9, (uint16_t)k, base + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1500);
        sp_rtp_recv(&rx, pkt, (size_t)n);
    }
    int clean = 0, max_q = 0;
    for (; k < 180; k++) {
        int n = mk_pkt(pkt, 9, (uint16_t)k, base + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1500);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        sp_rtp_recv(&rx, pkt, (size_t)n);       /* duplicate */
        sp_rtp_playout(&rx, out);
        if (k >= 90) {
            int q = (int32_t)(rx.rx_end_ts - rx.play_ts);
            if (q > max_q)
                max_q = q;
            if (frame_is(out, 1500))
                clean++;
        }
        if (k == 120) {                         /* one stray from long ago */
            int m = mk_pkt(pkt, 9, 1, base + SP_SAMPLES, SP_SAMPLES, 1500);
            sp_rtp_recv(&rx, pkt, (size_t)m);
        }
    }
    int final_q = (int32_t)(rx.rx_end_ts - rx.play_ts);
    CHECK(clean == 90, "audio clean after the burst, with duplicates and a stray: %d/90", clean);
    CHECK(max_q <= (rx.jb_target + 1 + 15) * SP_SAMPLES, "latency stays capped after the burst (max queued %d samples)", max_q);
    CHECK(final_q <= (rx.jb_target + 1 + 4) * SP_SAMPLES, "latency settles back down (queued %d, target %d)", final_q, rx.jb_target);
    CHECK(rx.rx_resync == 0, "duplicates and one stray never force a resync (%u)", rx.rx_resync);
}

/* LTE-like delivery: every packet delayed 0-140 ms (bursty), 1% spikes to
   300 ms. After a settling period, almost every frame should be real audio. */
static uint32_t lcg(uint32_t *s) { *s = *s * 1664525u + 1013904223u; return *s >> 8; }

static void t_lte_jitter(void)
{
    printf("[LTE-style jitter: adapts instead of chopping]\n");
    enum { N = 3000 };                       /* 60 s of packets */
    static int arrive[N];
    uint32_t seed = 12345;
    for (int i = 0; i < N; i++) {
        int jit = (int)(lcg(&seed) % 100);
        if (jit < 70) jit = (int)(lcg(&seed) % 40);          /* mostly 0-40 ms */
        else if (jit < 99) jit = 40 + (int)(lcg(&seed) % 100); /* bursts to 140 ms */
        else jit = 200 + (int)(lcg(&seed) % 100);              /* rare 200-300 ms spikes */
        arrive[i] = i * 20 + jit;
    }
    sp_rtp rx;
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    int real_late = 0, frames_late = 0, max_q = 0;
    int delivered[N] = { 0 };
    for (int tick = 0; tick < N; tick++) {
        int now = tick * 20 + 10;
        for (int i = 0; i < N; i++) {                       /* deliver everything that has arrived */
            if (!delivered[i] && arrive[i] <= now) {
                int n = mk_pkt(pkt, 3, (uint16_t)i, 1000 + (uint32_t)i * SP_SAMPLES, SP_SAMPLES, 1200);
                sp_rtp_recv(&rx, pkt, (size_t)n);
                delivered[i] = 1;
            }
            if (arrive[i] > now + 400)
                break;
        }
        int real = sp_rtp_playout(&rx, out);
        if (tick >= 1000) {                                  /* after 20 s of adaptation */
            frames_late++;
            real_late += real;
            int q = (int32_t)(rx.rx_end_ts - rx.play_ts);
            if (q > max_q)
                max_q = q;
        }
    }
    double pct = 100.0 * real_late / frames_late;
    CHECK(pct >= 98.5, "%.1f%% real frames once adapted (target %d, resync %u, trims %u)", pct, rx.jb_target,
          rx.rx_resync, rx.rx_trim);
    CHECK(max_q <= 500 * SP_CLOCK / 1000, "latency stays under 500 ms (max queued %d samples)", max_q);
}

/* ---- review findings (2026-10-12): adaptation must track jitter, not loss/pauses ---- */

/* 20 ms ticks; packet i arrives at i*20 + delay(i) ms, or never if dropped(i). */
typedef int (*delay_fn)(int i, uint32_t *seed);

static void run_net(sp_rtp *rx, int nframes, delay_fn delay, uint32_t seed, int *real_tail, int *q_tail_max,
                    int tail_from)
{
    static int arrive[6000];
    sp_rtp_init(rx, SP_PT_PCMU, -1);
    for (int i = 0; i < nframes; i++)
        arrive[i] = delay(i, &seed);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    int next = 0;
    *real_tail = 0;
    *q_tail_max = 0;
    for (int tick = 0; tick < nframes; tick++) {
        int now = tick * 20 + 10;
        for (int i = next > 40 ? next - 40 : 0; i < nframes && i * 20 <= now; i++) {
            if (arrive[i] >= 0 && arrive[i] <= now) {
                int n = mk_pkt(pkt, 1, (uint16_t)i, 5000 + (uint32_t)i * SP_SAMPLES, SP_SAMPLES, 900);
                sp_rtp_recv(rx, pkt, (size_t)n);
                arrive[i] = -2;                       /* delivered */
            }
            if (i > next)
                next = i;
        }
        int real = sp_rtp_playout(rx, out);
        if (tick >= tail_from) {
            *real_tail += real;
            int q = (int32_t)(rx->rx_end_ts - rx->play_ts);
            if (q > *q_tail_max)
                *q_tail_max = q;
        }
    }
}

static int d_loss1(int i, uint32_t *s) { return lcg(s) % 100 == 0 ? -1 : i * 20 + 3; }
static int d_talkspurts(int i, uint32_t *s) { (void)s; return (i % 125) < 75 ? i * 20 + 3 : -1; } /* 1.5 s on, 1 s off */
static int d_jitter_then_calm(int i, uint32_t *s)
{
    if (i >= 1000)
        return i * 20 + 5;                          /* calm after 20 s */
    int j = (int)(lcg(s) % 100);
    return i * 20 + (j < 70 ? (int)(lcg(s) % 40) : 40 + (int)(lcg(s) % 100));
}

static void t_adapt_only_on_jitter(void)
{
    printf("[delay adapts to jitter only, and gives it back]\n");
    sp_rtp rx;
    int real, qmax;
    run_net(&rx, 3000, d_loss1, 99, &real, &qmax, 2000);
    CHECK(rx.jb_target <= 3, "1%% loss with no jitter keeps the target low (%d)", rx.jb_target);
    CHECK(qmax <= (rx.jb_target + 2) * SP_SAMPLES, "  ...and the queue low (max %d samples)", qmax);
    run_net(&rx, 3000, d_talkspurts, 1, &real, &qmax, 2000);
    CHECK(rx.jb_target <= 3, "sender pauses (silence suppression) don't inflate the target (%d)", rx.jb_target);
    run_net(&rx, 6000, d_jitter_then_calm, 7, &real, &qmax, 5000);
    CHECK(rx.jb_target <= 3, "after the network calms, the target decays (%d)", rx.jb_target);
    CHECK(qmax <= (rx.jb_target + 2) * SP_SAMPLES, "  ...and the queue drains back to it (max %d, want %d)",
          qmax, (rx.jb_target + 1) * SP_SAMPLES);
    CHECK(real == 1000, "  ...with no audio lost while calm (%d/1000)", real);
}

static void t_offgrid_rebase(void)
{
    printf("[off-grid re-base with a thin buffer doesn't clip every frame]\n");
    sp_rtp rx;
    uint32_t a = 0x2000;
    uint32_t next = a + 100 * SP_SAMPLES;
    int g = run_switch(0xAAAA, a, 0xAAAA, next - 77, &rx);
    CHECK(g == 90, "jump back 77 samples: %d/90 clean", g);
    g = run_switch(0xAAAA, a, 0xAAAA, next - 300, &rx);
    CHECK(g == 90, "jump back 300 samples: %d/90 clean", g);
    g = run_switch(0xAAAA, a, 0xAAAA, next + 83, &rx);
    CHECK(g == 90, "jump ahead 83 samples: %d/90 clean", g);
    int stuck = 0;
    for (int j = 481; j <= 639; j += 2) {      /* 1.0.4 clipped half of every frame across this band */
        g = run_switch(0xAAAA, a, 0xAAAA, next - (uint32_t)j, &rx);
        if (g != 90)
            stuck++;
    }
    CHECK(stuck == 0, "jumps back 481-639 samples all play clean (%d stuck)", stuck);
}

static void t_drop_backlog(void)
{
    printf("[backlog after an audio-unit rebuild is dropped to the target]\n");
    sp_rtp rx;
    sp_rtp_init(&rx, SP_PT_PCMU, -1);
    uint8_t pkt[256];
    int16_t out[SP_SAMPLES];
    int k = 0;
    for (; k < 40; k++) {                       /* steady */
        int n = mk_pkt(pkt, 4, (uint16_t)k, 100 + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1100);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        sp_rtp_playout(&rx, out);
    }
    for (; k < 75; k++) {                       /* 700 ms rebuild: packets arrive, nothing plays */
        int n = mk_pkt(pkt, 4, (uint16_t)k, 100 + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1100);
        sp_rtp_recv(&rx, pkt, (size_t)n);
    }
    int dropped = sp_rtp_drop_backlog(&rx);
    int q = (int32_t)(rx.rx_end_ts - rx.play_ts);
    CHECK(dropped > 0 && q == (rx.jb_target + 1) * SP_SAMPLES, "dropped %d samples, queue now %d (want %d)",
          dropped, q, (rx.jb_target + 1) * SP_SAMPLES);
    int clean = 0;
    for (int j = 0; j < 20; j++, k++) {
        int n = mk_pkt(pkt, 4, (uint16_t)k, 100 + (uint32_t)k * SP_SAMPLES, SP_SAMPLES, 1100);
        sp_rtp_recv(&rx, pkt, (size_t)n);
        sp_rtp_playout(&rx, out);
        clean += frame_is(out, 1100);
    }
    CHECK(clean == 20, "audio continues cleanly after the drop (%d/20)", clean);
}

int main(void)
{
    t_codec();
    t_rtp_frame();
    t_jitter_reorder();
    t_loss();
    t_dtmf();
    t_recvonly();
    t_tx_first_then_rx();
    t_stream_jumps();
    t_ptime();
    t_stray_stream();
    t_jump_back_deep_queue();
    t_burst_and_strays();
    t_lte_jitter();
    t_adapt_only_on_jitter();
    t_offgrid_rebase();
    t_drop_backlog();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

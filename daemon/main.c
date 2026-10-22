/* sipphoned: the SIP Phone LaunchDaemon for iOS 6.
   Ties the verified SIP engine (sp_ua) to UDP/TCP sockets, RTP, the audio unit,
   and a Unix control socket the Phone/SpringBoard tweaks talk to. */
#include "sp_ua.h"
#include "sp_sip.h"
#include "sp_sdp.h"
#include "sp_rtp.h"
#include "sp_audio.h"
#include "sp_util.h"
#include "../common/sp_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <notify.h>

#include <CoreFoundation/CoreFoundation.h>

#define MAX_CLIENTS 8
#define RTP_PORT_BASE 40000
#define SP_STRICT_SOURCE 0   /* 1 = drop SIP/RTP from unexpected IPs. Only after the log shows none legit. */
#define NOTIFY_NET_CHANGE "com.apple.system.config.network_change"

typedef struct {
    sp_ua   *ua;
    sp_audio *audio;
    sp_cfg   cfg;

    int      sip_fd;          /* UDP or TCP, -1 while down */
    int      tcp_connected, tcp_connecting;
    char     tcp_rxbuf[16384];
    size_t   tcp_rxlen;
    int64_t  sip_retry_at;    /* reopen the SIP transport at this time, 0 = none */
    int      sip_backoff_ms;
    int64_t  last_sip_tx_ms;  /* for the NAT keepalive */

    int      rtp_fd;
    int      rtp_port;
    struct sockaddr_in rtp_remote;
    int      rtp_have_remote;
    int      rtp_mismatch_logged;

    struct sockaddr_in server_addr;
    char     local_ip[64];
    int      local_port;

    int      ctl_listen;
    int      ctl[MAX_CLIENTS];
    int      ctl_sub[MAX_CLIENTS];   /* client asked for the event stream (SUBSCRIBE) */

    int      notify_fd;
    int      notify_prefs_tok, notify_rereg_tok, notify_net_tok;
    int64_t  reload_at;              /* debounced prefs reload, 0 = none */
    int64_t  net_at;                 /* debounced network-change handling */
    int64_t  ended_clear_at;         /* ENDED -> IDLE after the UI has shown it */

    int      audio_up;
    int      media_on, media_pt, media_dtmf, media_send, media_recv;   /* last negotiated media */
    int64_t  audio_retry_at, watchdog_at;
    int      muted, speaker;
    int      audio_mode;             /* Settings > Call audio */
    int      bt_headset;             /* Settings > Use Bluetooth headset */
    int      capture_call;           /* this call is an echo test: record it (Detailed log only) */
    int64_t  quit_at;                /* SIGTERM: unregister, then exit */
} app;

static app g_app;
static char g_ctl_buf[MAX_CLIENTS][1024];   /* per-client partial command lines */
static int  g_ctl_len[MAX_CLIENTS];
static int  g_prev_call_state;
static volatile sig_atomic_t g_term;
/* RTP send results, written on the realtime audio thread */
static volatile uint32_t g_rtp_sent, g_rtp_send_errs;
static volatile int g_rtp_last_errno;
static int64_t g_stats_at;

static void on_term(int s)
{
    (void)s;
    g_term = 1;
}

static void min_deadline(int64_t *next, int64_t t)
{
    if (t > 0 && (*next <= 0 || t < *next))
        *next = t;
}

/* ----------------------------------------------------- CoreFoundation prefs */

static char *cf_str(CFDictionaryRef d, const char *key, const char *dflt, char *out, size_t n)
{
    out[0] = 0;
    if (dflt)
        sp_strlcpy(out, dflt, n);
    if (!d)
        return out;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    CFTypeRef v = CFDictionaryGetValue(d, k);
    CFRelease(k);
    if (v && CFGetTypeID(v) == CFStringGetTypeID())
        CFStringGetCString((CFStringRef)v, out, (CFIndex)n, kCFStringEncodingUTF8);
    return out;
}

static int cf_int(CFDictionaryRef d, const char *key, int dflt)
{
    if (!d)
        return dflt;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    CFTypeRef v = CFDictionaryGetValue(d, k);
    CFRelease(k);
    int out = dflt;
    if (v) {
        if (CFGetTypeID(v) == CFNumberGetTypeID())
            CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &out);
        else if (CFGetTypeID(v) == CFBooleanGetTypeID())
            out = CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
        else if (CFGetTypeID(v) == CFStringGetTypeID()) {
            char b[32];
            CFStringGetCString((CFStringRef)v, b, sizeof b, kCFStringEncodingUTF8);
            out = atoi(b);
        }
    }
    return out;
}

static CFDictionaryRef read_plist(const char *path)
{
    CFStringRef p = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, p, kCFURLPOSIXPathStyle, false);
    CFRelease(p);
    CFReadStreamRef rs = CFReadStreamCreateWithFile(NULL, url);
    CFRelease(url);
    if (!rs || !CFReadStreamOpen(rs)) {
        if (rs)
            CFRelease(rs);
        return NULL;
    }
    CFPropertyListRef pl = CFPropertyListCreateWithStream(NULL, rs, 0, kCFPropertyListImmutable,
                                                          NULL, NULL);
    CFReadStreamClose(rs);
    CFRelease(rs);
    if (pl && CFGetTypeID(pl) != CFDictionaryGetTypeID()) {
        CFRelease(pl);
        return NULL;
    }
    return (CFDictionaryRef)pl;
}

static void load_prefs(app *a)
{
    CFDictionaryRef d = read_plist(SP_PREFS_PATH);
    sp_cfg c;
    memset(&c, 0, sizeof c);
    cf_str(d, SP_PK_SERVER, "", c.server, sizeof c.server);
    cf_str(d, SP_PK_USER, "", c.user, sizeof c.user);
    cf_str(d, SP_PK_AUTHUSER, "", c.auth_user, sizeof c.auth_user);
    cf_str(d, SP_PK_PASSWORD, "", c.password, sizeof c.password);
    cf_str(d, SP_PK_DISPLAY, "", c.display, sizeof c.display);
    c.port = cf_int(d, SP_PK_PORT, 0);
    c.transport = cf_int(d, SP_PK_TRANSPORT, 0);
    c.expires = cf_int(d, SP_PK_EXPIRES, 300);
    c.do_register = cf_int(d, SP_PK_ENABLED, 0);
    sp_log_verbose = cf_int(d, SP_PK_DEBUG, 0);     /* off unless Settings > Troubleshooting turns it on */
    a->audio_mode = cf_int(d, SP_PK_AUDIO, 0);
    a->bt_headset = cf_int(d, SP_PK_BTHEADSET, 0);
    sp_strlcpy(c.user_agent, "SIPPhone/1.0 (iOS6)", sizeof c.user_agent);
    a->cfg = c;
    if (d)
        CFRelease(d);
    sp_log("prefs: server=%s user=%s enabled=%d transport=%d verbose=%d audio=%d", c.server, c.user,
           c.do_register, c.transport, sp_log_verbose, a->audio_mode);
}

/* ----------------------------------------------------- state publishing */

static void dict_set_str(CFMutableDictionaryRef d, const char *k, const char *v)
{
    CFStringRef ck = CFStringCreateWithCString(NULL, k, kCFStringEncodingUTF8);
    CFStringRef cv = CFStringCreateWithCString(NULL, v ? v : "", kCFStringEncodingUTF8);
    CFDictionarySetValue(d, ck, cv);
    CFRelease(ck);
    CFRelease(cv);
}

static void dict_set_int(CFMutableDictionaryRef d, const char *k, long long v)
{
    CFStringRef ck = CFStringCreateWithCString(NULL, k, kCFStringEncodingUTF8);
    CFNumberRef cv = CFNumberCreate(NULL, kCFNumberLongLongType, &v);
    CFDictionarySetValue(d, ck, cv);
    CFRelease(ck);
    CFRelease(cv);
}

static void write_state(app *a)
{
    sp_call_info ci;
    sp_ua_call(a->ua, &ci);
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                                         &kCFTypeDictionaryValueCallBacks);
    dict_set_int(d, SP_K_REG_STATE, sp_ua_reg_state(a->ua));
    dict_set_str(d, SP_K_REG_DETAIL, sp_ua_reg_detail(a->ua));
    dict_set_int(d, SP_K_CALL_STATE, ci.state);
    dict_set_int(d, SP_K_CALL_INCOMING, ci.incoming);
    dict_set_str(d, SP_K_CALL_NUMBER, ci.number);
    dict_set_str(d, SP_K_CALL_DISPLAY, ci.display);
    dict_set_str(d, SP_K_CALL_REASON, ci.reason);
    dict_set_int(d, SP_K_CALL_MUTED, a->muted);
    dict_set_int(d, SP_K_CALL_HELD, ci.held);
    dict_set_int(d, SP_K_CALL_SPEAKER, a->speaker);
    dict_set_int(d, SP_K_CALL_START, ci.connected_at);
    dict_set_int(d, SP_K_CALL_ID, ci.id);

    CFDataRef data = CFPropertyListCreateData(NULL, d, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    CFRelease(d);
    if (data) {
        char tmp[320];
        snprintf(tmp, sizeof tmp, "%s.tmp", SP_STATE_PATH);
        FILE *f = fopen(tmp, "wb");
        if (f) {
            fwrite(CFDataGetBytePtr(data), 1, (size_t)CFDataGetLength(data), f);
            fclose(f);
            rename(tmp, SP_STATE_PATH);
            chmod(SP_STATE_PATH, 0644);
        }
        CFRelease(data);
    }
}

static void ctl_drop(app *a, int i)
{
    close(a->ctl[i]);
    a->ctl[i] = -1;
    a->ctl_sub[i] = 0;
}

/* Best-effort write to one client. SIGPIPE is ignored process-wide, so a
   client that already hung up just yields EPIPE and gets dropped. */
static void ctl_reply(app *a, int i, const char *line)
{
    if (a->ctl[i] < 0)
        return;
    ssize_t r = write(a->ctl[i], line, strlen(line));
    if (r < 0 && errno != EAGAIN && errno != EINTR)
        ctl_drop(a, i);
}

/* Events only go to clients that subscribed. The UI tweaks send one command
   and hang up (they read the state plist), so they are never written to. */
static void ctl_broadcast(app *a, const char *line)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (a->ctl[i] >= 0 && a->ctl_sub[i])
            ctl_reply(a, i, line);
}

static void state_lines(app *a, char *call, size_t cn, char *reg, size_t rn)
{
    sp_call_info ci;
    sp_ua_call(a->ua, &ci);
    snprintf(call, cn, "CALL %d %d %d %d %d %s | %s\n", ci.state, ci.incoming, a->muted, ci.held,
             a->speaker, ci.number[0] ? ci.number : "-", ci.display);
    snprintf(reg, rn, "REG %d %s\n", sp_ua_reg_state(a->ua), sp_ua_reg_detail(a->ua));
}

static void publish(app *a, int incoming_edge)
{
    write_state(a);
    notify_post(SP_NOTIFY_STATE);
    if (incoming_edge)
        notify_post(SP_NOTIFY_INCOMING);
    char call[512], reg[160];
    state_lines(a, call, sizeof call, reg, sizeof reg);
    ctl_broadcast(a, call);
    ctl_broadcast(a, reg);
}

/* ----------------------------------------------------- audio + sp_ua hooks */

/* mute/speaker go in BEFORE the start so the route applied inside
   sp_audio_start uses this call's state */
static int ensure_audio(app *a)
{
    if (a->audio_up)
        return 0;
    sp_audio_set_mute(a->audio, a->muted);
    sp_audio_set_speaker(a->audio, a->speaker);
    sp_audio_set_mode(a->audio, a->audio_mode);
    sp_audio_set_bluetooth(a->audio, a->bt_headset);
    sp_audio_set_capture(a->audio, a->capture_call);  /* echo-test calls only, never a person */
    if (sp_audio_start(a->audio, SP_PT_PCMU, -1, 1, 1) != 0) {
        sp_log("audio: start failed, retrying");
        a->audio_retry_at = sp_now_ms() + 1000;
        return -1;
    }
    a->audio_up = 1;
    return 0;
}

static void stop_audio(app *a)
{
    sp_audio_stop(a->audio);              /* no-op when nothing is up; cleans a half-built unit */
    a->audio_up = 0;
    a->rtp_have_remote = 0;
    a->media_on = 0;
}

/* hold silences the mic but keeps RTP flowing (NAT binding, server RTP timers) */
static void apply_mute(app *a)
{
    sp_call_info ci;
    sp_ua_call(a->ua, &ci);
    sp_audio_set_mute(a->audio, a->muted || ci.held);
}

static void reset_call_controls(app *a)
{
    a->muted = 0;
    a->speaker = 0;
    sp_audio_set_mute(a->audio, 0);
    sp_audio_set_speaker(a->audio, 0);    /* only re-routes while running */
}

static void hook_send(void *ctx, const char *data, size_t len)
{
    app *a = ctx;
    if (a->sip_fd < 0)
        return;
    ssize_t r;
    if (a->cfg.transport == SP_TP_TCP) {
        if (!a->tcp_connected)
            return;
        r = send(a->sip_fd, data, len, 0);
    } else {
        r = sendto(a->sip_fd, data, len, 0, (struct sockaddr *)&a->server_addr, sizeof a->server_addr);
    }
    if (r < 0) {
        sp_log("sip send failed: %s", strerror(errno));
        if (errno == ENETUNREACH || errno == EHOSTUNREACH || errno == EADDRNOTAVAIL || errno == ENETDOWN)
            a->net_at = sp_now_ms() + 2000;           /* treat as a network change */
    } else {
        a->last_sip_tx_ms = sp_now_ms();
    }
}

static void hook_changed(void *ctx)
{
    app *a = ctx;
    sp_call_info ci;
    sp_ua_call(a->ua, &ci);
    if (ci.state == SP_CALL_ENDED || ci.state == SP_CALL_IDLE) {
        stop_audio(a);                    /* also ringback-only audio, where media_on was never set */
        reset_call_controls(a);           /* next call never starts muted / on speaker */
    }
    publish(a, 0);
}

static void hook_media(void *ctx, int on, const char *ip, int port, int pt, int dtmf_pt, int dir)
{
    app *a = ctx;
    if (!on) {
        stop_audio(a);
        return;
    }
    a->rtp_remote.sin_family = AF_INET;
    a->rtp_remote.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &a->rtp_remote.sin_addr);
    a->rtp_have_remote = 1;
    a->rtp_mismatch_logged = 0;
    a->media_on = 1;
    a->media_pt = pt;
    a->media_dtmf = dtmf_pt;
    a->media_send = dir == SP_DIR_SENDRECV || dir == SP_DIR_SENDONLY;
    a->media_recv = dir == SP_DIR_SENDRECV || dir == SP_DIR_RECVONLY;
    if (ensure_audio(a) == 0)
        sp_audio_reconfigure(a->audio, pt, dtmf_pt, a->media_send, a->media_recv);
    apply_mute(a);
    sp_log("media up -> %s:%d pt%d dir%d", ip, port, pt, dir);
}

static void hook_tone(void *ctx, int tone)
{
    app *a = ctx;
    if (tone == SP_TONE_NONE) {
        if (a->audio_up)
            sp_audio_set_tone(a->audio, SP_AU_TONE_NONE);
        return;
    }
    if (ensure_audio(a) == 0)
        sp_audio_set_tone(a->audio, tone == SP_TONE_BUSY ? SP_AU_TONE_BUSY : SP_AU_TONE_RINGBACK);
}

/* RTP out, called from the realtime audio thread */
static void audio_tx(void *ctx, const uint8_t *pkt, int len)
{
    app *a = ctx;
    if (!a->rtp_have_remote || a->rtp_fd < 0)
        return;
    ssize_t r = sendto(a->rtp_fd, pkt, (size_t)len, 0, (struct sockaddr *)&a->rtp_remote,
                       sizeof a->rtp_remote);
    if (r < 0) {
        g_rtp_send_errs++;
        g_rtp_last_errno = errno;
    } else {
        g_rtp_sent++;
    }
}

/* ----------------------------------------------------- sockets */

static int open_rtp(app *a)
{
    for (int p = RTP_PORT_BASE; p < RTP_PORT_BASE + 200; p += 2) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
            return -1;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = htons((uint16_t)p);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
            fcntl(fd, F_SETFL, O_NONBLOCK);
            a->rtp_fd = fd;
            a->rtp_port = p;
            return 0;
        }
        close(fd);
    }
    return -1;
}

static int resolve_server(app *a, struct sockaddr_in *out)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", a->cfg.port ? a->cfg.port : 5060);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = a->cfg.transport == SP_TP_TCP ? SOCK_STREAM : SOCK_DGRAM;
    if (getaddrinfo(a->cfg.server, portstr, &hints, &res) != 0 || !res) {
        sp_log("cannot resolve %s", a->cfg.server);
        return -1;
    }
    memcpy(out, res->ai_addr, sizeof *out);
    freeaddrinfo(res);
    return 0;
}

/* local IP that reaches the server (connected-UDP getsockname trick) */
static void discover_local_ip(app *a)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa = a->server_addr;
    connect(fd, (struct sockaddr *)&sa, sizeof sa);
    struct sockaddr_in local;
    socklen_t sl = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &sl) == 0)
        inet_ntop(AF_INET, &local.sin_addr, a->local_ip, sizeof a->local_ip);
    else
        sp_strlcpy(a->local_ip, "0.0.0.0", sizeof a->local_ip);
    close(fd);
}

/* Transport went away: close it and schedule a reopen with backoff
   (5 s, 10 s, 20 s, 40 s, then every 60 s). */
static void sip_down(app *a, const char *why)
{
    sp_log("sip transport down: %s", why);
    if (a->sip_fd >= 0)
        close(a->sip_fd);
    a->sip_fd = -1;
    a->tcp_connected = a->tcp_connecting = 0;
    a->tcp_rxlen = 0;
    sp_ua_transport_reset(a->ua);
    a->sip_backoff_ms = !a->sip_backoff_ms ? 5000 : (a->sip_backoff_ms >= 30000 ? 60000 : a->sip_backoff_ms * 2);
    a->sip_retry_at = sp_now_ms() + a->sip_backoff_ms;
}

/* The server can't be reached (DNS failure or no network): close the socket,
   schedule the backoff reopen, and publish a clear reason instead of letting
   REGISTERs time out into "No response from server". */
static void sip_unreachable(app *a, const char *why)
{
    sip_down(a, why);
    char msg[160];
    snprintf(msg, sizeof msg, "Can't reach %s (no network?)", a->cfg.server);
    sp_ua_set_unreachable(a->ua, msg);
}

/* Resolves first: a DNS failure returns -1 and leaves any existing socket
   alone. Any other -1 leaves a socket for the caller's sip_down() to close. */
static int open_sip(app *a)
{
    struct sockaddr_in srv;
    if (resolve_server(a, &srv) != 0)
        return -1;
    if (a->sip_fd >= 0)
        close(a->sip_fd);
    a->sip_fd = -1;
    a->tcp_connected = a->tcp_connecting = 0;
    a->tcp_rxlen = 0;
    a->server_addr = srv;
    discover_local_ip(a);
    if (a->cfg.transport == SP_TP_TCP) {
        a->sip_fd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(a->sip_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        fcntl(a->sip_fd, F_SETFL, O_NONBLOCK);
        int r = connect(a->sip_fd, (struct sockaddr *)&a->server_addr, sizeof a->server_addr);
        if (r == 0)
            a->tcp_connected = 1;
        else if (errno == EINPROGRESS)
            a->tcp_connecting = 1;
        else
            return -1;
        a->local_port = 0;
    } else {
        a->sip_fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = htons(5060);
        if (bind(a->sip_fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
            sa.sin_port = 0;   /* fall back to an ephemeral port */
            bind(a->sip_fd, (struct sockaddr *)&sa, sizeof sa);
        }
        struct sockaddr_in got;
        socklen_t gl = sizeof got;
        getsockname(a->sip_fd, (struct sockaddr *)&got, &gl);
        a->local_port = ntohs(got.sin_port);
        fcntl(a->sip_fd, F_SETFL, O_NONBLOCK);
    }
    sp_ua_set_local(a->ua, a->local_ip, a->local_port);
    sp_ua_set_rtp_port(a->ua, a->rtp_port);
    if (a->cfg.transport != SP_TP_TCP)
        a->sip_backoff_ms = 0;
    a->sip_retry_at = 0;
    sp_log("sip socket up local %s:%d -> %s", a->local_ip, a->local_port, a->cfg.server);
    return 0;
}

static void on_tcp_writable(app *a)
{
    if (!a->tcp_connecting)
        return;
    int err = 0;
    socklen_t el = sizeof err;
    getsockopt(a->sip_fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) {
        sip_down(a, strerror(err));
        return;
    }
    a->tcp_connecting = 0;
    a->tcp_connected = 1;
    a->sip_backoff_ms = 0;
    struct sockaddr_in got;
    socklen_t gl = sizeof got;
    getsockname(a->sip_fd, (struct sockaddr *)&got, &gl);
    a->local_port = ntohs(got.sin_port);
    inet_ntop(AF_INET, &got.sin_addr, a->local_ip, sizeof a->local_ip);
    sp_ua_set_local(a->ua, a->local_ip, a->local_port);
    sp_log("tcp connected, local %s:%d", a->local_ip, a->local_port);
    sp_ua_refresh_now(a->ua);
}

/* Wi-Fi <-> LTE or a new address: no DNS here (reuses server_addr), and it
   never leaves the daemon without a socket. */
static void net_changed(app *a)
{
    if (!a->cfg.server[0] || !a->cfg.do_register)
        return;
    if (a->sip_fd < 0) {
        a->sip_retry_at = sp_now_ms();
        return;
    }
    char old[64];
    sp_strlcpy(old, a->local_ip, sizeof old);
    discover_local_ip(a);
    if (strcmp(a->local_ip, "0.0.0.0") == 0) {       /* no route yet: the next notify retries */
        sp_strlcpy(a->local_ip, old, sizeof a->local_ip);
        return;
    }
    int ipchg = strcmp(old, a->local_ip) != 0;
    if (a->cfg.transport == SP_TP_TCP) {
        if (ipchg) {
            sip_down(a, "network changed");
            a->sip_retry_at = sp_now_ms();
        }
        return;
    }
    if (!ipchg) {
        /* iOS posts network_change about once a minute on Wi-Fi with nothing changed
           for us (cellular/IPv6 churn). Same address = same NAT path: just poke it;
           the regular refresh re-learns the public address anyway. */
        hook_send(a, "\r\n\r\n", 4);
        return;
    }
    sp_log("network changed: local %s -> %s, re-registering", old, a->local_ip);
    sp_ua_set_local(a->ua, "", 0);                      /* forget the learned public address, even if */
    sp_ua_set_local(a->ua, a->local_ip, a->local_port); /* the private IP did not change */
    sp_ua_refresh_now(a->ua);
}

static void on_sip_readable(app *a)
{
    if (a->sip_fd < 0)
        return;
    if (a->cfg.transport == SP_TP_TCP) {
        ssize_t r = recv(a->sip_fd, a->tcp_rxbuf + a->tcp_rxlen,
                         sizeof a->tcp_rxbuf - a->tcp_rxlen, 0);
        if (r <= 0) {
            if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                sip_down(a, r == 0 ? "tcp closed by server" : strerror(errno));
            return;
        }
        a->tcp_rxlen += (size_t)r;
        for (;;) {
            long n = sp_frame(a->tcp_rxbuf, a->tcp_rxlen);
            if (n == 0)
                break;
            if (n < 0) {
                size_t skip = (size_t)(-n);
                memmove(a->tcp_rxbuf, a->tcp_rxbuf + skip, a->tcp_rxlen - skip);
                a->tcp_rxlen -= skip;
                continue;
            }
            sp_ua_input(a->ua, a->tcp_rxbuf, (size_t)n);
            memmove(a->tcp_rxbuf, a->tcp_rxbuf + n, a->tcp_rxlen - (size_t)n);
            a->tcp_rxlen -= (size_t)n;
        }
    } else {
        char buf[4096];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(a->sip_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            return;
        ssize_t k = 0;
        while (k < r && (buf[k] == '\r' || buf[k] == '\n'))
            k++;
        if (k == r)
            return;                                       /* keepalive pong */
        if (from.sin_addr.s_addr != a->server_addr.sin_addr.s_addr) {   /* IP only, never the port */
            char ip[64];
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
            sp_log("udp from %s:%d is not the server%s", ip, ntohs(from.sin_port),
                   SP_STRICT_SOURCE ? ", dropped" : "");
            if (SP_STRICT_SOURCE)
                return;
        } else if (sp_log_verbose && from.sin_port != a->server_addr.sin_port) {
            sp_log("udp from the server IP but port %d", ntohs(from.sin_port));
        }
        sp_ua_input(a->ua, buf, (size_t)r);
    }
}

static void on_rtp_readable(app *a)
{
    uint8_t buf[2048];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(a->rtp_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        if (!a->audio_up || !a->rtp_have_remote)
            continue;                                  /* stray / previous call */
        if (from.sin_addr.s_addr != a->rtp_remote.sin_addr.s_addr) {   /* IP only, never the port */
            if (!a->rtp_mismatch_logged++) {
                char ip[64];
                inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
                sp_log("rtp from %s is not the SDP address%s", ip, SP_STRICT_SOURCE ? ", dropping" : "");
            }
            if (SP_STRICT_SOURCE)
                continue;                              /* keep draining */
        }
        sp_audio_rtp_in(a->audio, buf, (int)r);
    }
}

/* ----------------------------------------------------- dialing */

/* The Phone app passes the number as displayed ("(312) 555-1234",
   "+1 312-555-1234"). A SIP request line can't carry spaces or parentheses,
   so keep only digits * # + and map E.164 to what VoIP.ms dials:
   +1NXXNXXXXXX -> 1NXXNXXXXXX, other +CC... -> 011CC... */
static int normalize_number(const char *in, char *out, size_t n)
{
    char t[64];
    size_t k = 0;
    for (const char *p = in; *p && k + 1 < sizeof t; p++) {
        if (*p == ',' || *p == ';')
            break;                        /* pause/wait: dial the number, key the rest on the keypad */
        if ((*p >= '0' && *p <= '9') || *p == '*' || *p == '#' || (*p == '+' && k == 0))
            t[k++] = *p;
    }
    t[k] = 0;
    if (!k || (k == 1 && t[0] == '+'))
        return -1;
    if (t[0] == '+' && t[1] == '1')
        snprintf(out, n, "%s", t + 1);
    else if (t[0] == '+')
        snprintf(out, n, "011%s", t + 1);
    else
        snprintf(out, n, "%s", t);
    return 0;
}

/* ----------------------------------------------------- prefs apply */

static int transport_changed(const sp_cfg *o, const sp_cfg *n)
{
    return strcmp(o->server, n->server) != 0 || o->port != n->port || o->transport != n->transport;
}

static int account_changed(const sp_cfg *o, const sp_cfg *n)
{
    return strcmp(o->user, n->user) != 0 || strcmp(o->auth_user, n->auth_user) != 0 ||
           strcmp(o->password, n->password) != 0 || strcmp(o->display, n->display) != 0 ||
           o->expires != n->expires || o->do_register != n->do_register;
}

/* Re-read prefs and touch only what changed: reopen the socket only for a
   server/port/transport change, re-register only for an account change.
   force = "Re-register now": re-register even if nothing changed. Never tears
   the transport down under a live call (re-armed instead). */
static void apply_prefs(app *a, int force)
{
    sp_cfg old = a->cfg;
    load_prefs(a);
    int busy = sp_ua_busy(a->ua);
    int tchg = transport_changed(&old, &a->cfg) || a->sip_fd < 0 || (force && !busy);
    int achg = account_changed(&old, &a->cfg) || force;
    if (!tchg && !achg) {
        sp_log("prefs: nothing that matters changed");
        return;
    }
    if (tchg && busy) {
        sp_log("prefs: transport change deferred until the call ends");
        a->cfg = old;
        a->reload_at = sp_now_ms() + 3000;
        return;
    }
    if (old.do_register && !a->cfg.do_register) {
        if (transport_changed(&old, &a->cfg)) {
            /* keep describing the socket that is actually open, so Expires: 0
               goes out on it and re-enabling later sees the change and reopens */
            sp_strlcpy(a->cfg.server, old.server, sizeof a->cfg.server);
            a->cfg.port = old.port;
            a->cfg.transport = old.transport;
        }
        sp_ua_unregister(a->ua);          /* REGISTER Expires: 0 on the old transport */
        sp_ua_configure(a->ua, &a->cfg);
        return;
    }
    sp_ua_configure(a->ua, &a->cfg);
    if (tchg && a->cfg.server[0] && a->cfg.do_register) {
        sp_ua_transport_reset(a->ua);
        a->sip_backoff_ms = 0;
        if (open_sip(a) != 0) {
            sip_unreachable(a, "cannot open after prefs change");   /* also closes a socket aimed at the old server */
            return;
        }
    }
    sp_ua_start(a->ua);
}

/* ----------------------------------------------------- control socket */

static void handle_command(app *a, int idx, char *line)
{
    while (*line == ' ')
        line++;
    char *sp = strchr(line, ' ');
    char *arg = sp ? sp + 1 : (char *)"";
    if (sp)
        *sp = 0;
    char *nl = strpbrk(arg, "\r\n");
    if (nl)
        *nl = 0;

    if (sp_strcaseeq(line, "DIAL")) {
        char num[64];
        if (normalize_number(arg, num, sizeof num) != 0) {
            sp_log("dial: nothing dialable in '%s'", arg);
            return;
        }
        if (sp_ua_busy(a->ua)) {
            sp_log("dial: already in a call, ignoring");
            return;
        }
        sp_ua_clear_ended(a->ua);
        reset_call_controls(a);
        a->capture_call = sp_log_verbose && strcmp(num, "4443") == 0;   /* VoIP.ms echo test */
        if (sp_ua_dial(a->ua, num) < 0)
            sp_log("dial: refused (account not set up?)");
    } else if (sp_strcaseeq(line, "ANSWER")) {
        sp_ua_answer(a->ua);
    } else if (sp_strcaseeq(line, "HANGUP")) {
        sp_ua_hangup(a->ua);
    } else if (sp_strcaseeq(line, "HOLD")) {
        sp_ua_hold(a->ua, atoi(arg));
        apply_mute(a);                    /* hold also silences the mic */
        publish(a, 0);
    } else if (sp_strcaseeq(line, "MUTE")) {
        a->muted = atoi(arg);
        apply_mute(a);
        publish(a, 0);
    } else if (sp_strcaseeq(line, "SPEAKER")) {
        a->speaker = atoi(arg);
        sp_audio_set_speaker(a->audio, a->speaker);   /* safe while audio is stopped */
        publish(a, 0);
    } else if (sp_strcaseeq(line, "DTMF")) {
        if (a->audio_up && arg[0])
            sp_audio_send_dtmf(a->audio, arg[0]);
    } else if (sp_strcaseeq(line, "RELOAD")) {
        apply_prefs(a, 1);
    } else if (sp_strcaseeq(line, "SUBSCRIBE") || sp_strcaseeq(line, "STATUS")) {
        if (sp_strcaseeq(line, "SUBSCRIBE"))
            a->ctl_sub[idx] = 1;
        char call[512], reg[160];
        state_lines(a, call, sizeof call, reg, sizeof reg);
        ctl_reply(a, idx, call);
        ctl_reply(a, idx, reg);
    } else if (sp_strcaseeq(line, "PING")) {
        ctl_reply(a, idx, "PONG\n");
    } else {
        sp_log("control: unknown command '%s'", line);
    }
}

static void on_ctl_readable(app *a, int idx)
{
    for (;;) {
        if (a->ctl[idx] < 0)
            return;
        int room = (int)sizeof g_ctl_buf[idx] - 1 - g_ctl_len[idx];
        if (room <= 0) {
            sp_log("control: line too long, dropping client");
            g_ctl_len[idx] = 0;
            ctl_drop(a, idx);
            return;
        }
        ssize_t r = read(a->ctl[idx], g_ctl_buf[idx] + g_ctl_len[idx], (size_t)room);
        if (r < 0 && (errno == EAGAIN || errno == EINTR))
            return;                              /* nothing more right now */
        int eof = r <= 0;
        if (r > 0)
            g_ctl_len[idx] += (int)r;
        g_ctl_buf[idx][g_ctl_len[idx]] = 0;
        char *start = g_ctl_buf[idx], *nl;
        while ((nl = strchr(start, '\n'))) {
            *nl = 0;
            if (*start)
                handle_command(a, idx, start);
            start = nl + 1;
            if (a->ctl[idx] < 0) {               /* dropped while replying */
                g_ctl_len[idx] = 0;
                return;
            }
        }
        if (eof && *start)
            handle_command(a, idx, start);       /* last command had no newline */
        int rem = eof ? 0 : (int)(g_ctl_buf[idx] + g_ctl_len[idx] - start);
        memmove(g_ctl_buf[idx], start, (size_t)rem);
        g_ctl_len[idx] = rem;
        if (eof) {
            if (a->ctl[idx] >= 0)
                ctl_drop(a, idx);
            return;
        }
    }
}

static void on_ctl_accept(app *a)
{
    int fd = accept(a->ctl_listen, NULL, NULL);
    if (fd < 0)
        return;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (a->ctl[i] < 0) {
            a->ctl[i] = fd;
            a->ctl_sub[i] = 0;
            g_ctl_len[i] = 0;
            /* Never write here: the Phone hook sends "DIAL n" and hangs up at
               once. Read whatever it already sent instead. */
            on_ctl_readable(a, i);
            return;
        }
    sp_log("control: too many clients, dropping one");
    close(fd);
}

static int open_control(app *a)
{
    unlink(SP_SOCK_PATH);
    a->ctl_listen = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    sp_strlcpy(sa.sun_path, SP_SOCK_PATH, sizeof sa.sun_path);
    if (bind(a->ctl_listen, (struct sockaddr *)&sa, sizeof sa) != 0) {
        sp_log("control bind failed: %s", strerror(errno));
        return -1;
    }
    chmod(SP_SOCK_PATH, 0666);   /* mobile (Phone/SpringBoard) must connect */
    listen(a->ctl_listen, 8);
    fcntl(a->ctl_listen, F_SETFL, O_NONBLOCK);
    return 0;
}

/* ----------------------------------------------------- main loop */

int main(void)
{
    /* A client that hangs up before we write (the Phone hook does exactly
       that) must cost an EPIPE, never the whole daemon. */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_term);             /* launchctl unload / dpkg: unregister first */

    app *a = &g_app;
    memset(a, 0, sizeof *a);
    a->sip_fd = a->rtp_fd = a->ctl_listen = a->notify_fd = -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
        a->ctl[i] = -1;

    sp_log_open(SP_LOG_PATH);
    sp_log_verbose = 0;
    sp_log("sipphoned starting");

    sp_hooks h = { 0 };
    h.ctx = a;
    h.send = hook_send;
    h.changed = hook_changed;
    h.media = hook_media;
    h.tone = hook_tone;
    a->ua = sp_ua_new(&h);
    a->audio = sp_audio_new(audio_tx, a);
    sp_audio_delete_captures();           /* debug recordings never outlive the daemon */

    open_rtp(a);
    open_control(a);
    load_prefs(a);
    sp_ua_configure(a->ua, &a->cfg);
    if (!a->cfg.server[0] || !a->cfg.do_register)
        sp_ua_start(a->ua);                       /* shows "Off" / "Not set up" */
    else if (open_sip(a) == 0)
        sp_ua_start(a->ua);
    else
        sip_unreachable(a, "cannot open at startup (network not up yet?)");

    notify_register_file_descriptor(SP_NOTIFY_PREFS, &a->notify_fd, 0, &a->notify_prefs_tok);
    notify_register_file_descriptor(SP_NOTIFY_REREGISTER, &a->notify_fd, NOTIFY_REUSE,
                                    &a->notify_rereg_tok);
    notify_register_file_descriptor(NOTIFY_NET_CHANGE, &a->notify_fd, NOTIFY_REUSE,
                                    &a->notify_net_tok);
    publish(a, 0);
    g_prev_call_state = SP_CALL_IDLE;

    for (;;) {
        struct pollfd pf[MAX_CLIENTS + 5];
        int n = 0;
        int i_sip = -1, i_rtp = -1, i_ctl = -1, i_nfy = -1;
        if (a->sip_fd >= 0) {
            pf[n].fd = a->sip_fd;
            pf[n].events = POLLIN;
            if (a->cfg.transport == SP_TP_TCP && a->tcp_connecting)
                pf[n].events |= POLLOUT;
            i_sip = n++;
        }
        if (a->rtp_fd >= 0) {
            pf[n].fd = a->rtp_fd;
            pf[n].events = POLLIN;
            i_rtp = n++;
        }
        if (a->ctl_listen >= 0) {
            pf[n].fd = a->ctl_listen;
            pf[n].events = POLLIN;
            i_ctl = n++;
        }
        if (a->notify_fd >= 0) {
            pf[n].fd = a->notify_fd;
            pf[n].events = POLLIN;
            i_nfy = n++;
        }
        int ci[MAX_CLIENTS];
        for (int i = 0; i < MAX_CLIENTS; i++) {
            ci[i] = -1;
            if (a->ctl[i] >= 0) {
                pf[n].fd = a->ctl[i];
                pf[n].events = POLLIN;
                ci[i] = n++;
            }
        }

        int64_t next = sp_ua_next_timer(a->ua);
        min_deadline(&next, a->reload_at);
        min_deadline(&next, a->sip_retry_at);
        min_deadline(&next, a->net_at);
        min_deadline(&next, a->ended_clear_at);
        min_deadline(&next, a->quit_at);
        int64_t nowm = sp_now_ms();
        /* AudioSession callbacks (interruptions, route changes, media server
           death) only arrive while the run loop is pumped, so poll often
           while call audio is up */
        int timeout = a->audio_up ? 100 : 1000;
        if (next > 0) {
            int64_t dt = next - nowm;
            if (dt < 0)
                dt = 0;
            if (dt < timeout)
                timeout = (int)dt;
        }

        int r = poll(pf, (nfds_t)n, timeout);
        (void)r;
        while (CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true) == kCFRunLoopRunHandledSource)
            ;

        int prev_state = g_prev_call_state;

        if (i_sip >= 0 && a->sip_fd >= 0 && (pf[i_sip].revents & POLLOUT))
            on_tcp_writable(a);
        if (i_sip >= 0 && a->sip_fd >= 0 && (pf[i_sip].revents & (POLLIN | POLLHUP | POLLERR)))
            on_sip_readable(a);
        if (i_rtp >= 0 && (pf[i_rtp].revents & POLLIN))
            on_rtp_readable(a);
        if (i_ctl >= 0 && (pf[i_ctl].revents & POLLIN))
            on_ctl_accept(a);
        if (i_nfy >= 0 && (pf[i_nfy].revents & POLLIN)) {
            int tok;
            if (read(a->notify_fd, &tok, sizeof tok) == (ssize_t)sizeof tok) {
                tok = (int)ntohl((uint32_t)tok);          /* notify writes tokens in network byte order */
                if (tok == a->notify_rereg_tok) {
                    a->reload_at = 0;
                    sp_log("re-register requested");
                    apply_prefs(a, 1);
                } else if (tok == a->notify_net_tok) {
                    a->net_at = sp_now_ms() + 2000;       /* configd posts in bursts */
                } else {
                    a->reload_at = sp_now_ms() + 1500;    /* settle: one reload per burst of edits */
                }
            }
        }
        if (a->reload_at > 0 && sp_now_ms() >= a->reload_at) {
            a->reload_at = 0;
            sp_log("prefs changed: applying");
            apply_prefs(a, 0);
        }
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (ci[i] >= 0 && (pf[ci[i]].revents & (POLLIN | POLLHUP)))
                on_ctl_readable(a, i);

        int64_t now = sp_now_ms();
        if (a->sip_fd < 0 && a->sip_retry_at && now >= a->sip_retry_at &&
            a->cfg.server[0] && a->cfg.do_register) {
            a->sip_retry_at = 0;
            if (open_sip(a) == 0)
                sp_ua_start(a->ua);
            else
                sip_unreachable(a, "reopen failed");
        }
        if (a->net_at && now >= a->net_at) {
            a->net_at = 0;
            net_changed(a);
        }

        sp_ua_tick(a->ua);

        /* NAT keepalive: a bare CRLFCRLF keeps the router/carrier mapping open
           between the 255 s re-REGISTERs so inbound INVITEs still get through */
        if (a->sip_fd >= 0 && sp_ua_reg_state(a->ua) == SP_REG_OK &&
            sp_now_ms() - a->last_sip_tx_ms >= (a->cfg.transport == SP_TP_TCP ? 90000 : 25000))
            hook_send(a, "\r\n\r\n", 4);

        /* restart dead call audio (failed start, media server reset) */
        if (a->media_on && sp_ua_busy(a->ua) && sp_now_ms() >= a->audio_retry_at &&
            (!a->audio_up || !sp_audio_is_running(a->audio))) {
            a->audio_retry_at = sp_now_ms() + 1000;
            a->audio_up = 0;
            if (ensure_audio(a) == 0) {
                sp_audio_reconfigure(a->audio, a->media_pt, a->media_dtmf, a->media_send, a->media_recv);
                apply_mute(a);
            }
        }
        if (a->audio_up)
            sp_audio_service(a->audio);           /* route change -> voice processing on/off */
        if (a->audio_up && sp_log_verbose && sp_now_ms() >= g_stats_at) {
            g_stats_at = sp_now_ms() + 2000;
            char dbg[256], rip[64];
            sp_audio_debug(a->audio, dbg, sizeof dbg);
            inet_ntop(AF_INET, &a->rtp_remote.sin_addr, rip, sizeof rip);
            sp_log("audio stats: %s | sendto ok=%u err=%u(errno %d) -> %s:%d", dbg,
                   (unsigned)g_rtp_sent, (unsigned)g_rtp_send_errs, g_rtp_last_errno, rip,
                   ntohs(a->rtp_remote.sin_port));
        }
        if (a->audio_up && sp_now_ms() >= a->watchdog_at) {
            a->watchdog_at = sp_now_ms() + 1000;
            sp_audio_watchdog(a->audio);
            if (sp_audio_take_route_change(a->audio)) {
                a->speaker = 0;                       /* headset plugged/unplugged dropped speaker */
                publish(a, 0);
            }
        }

        sp_call_info ci2;
        sp_ua_call(a->ua, &ci2);
        /* IDLE/ENDED -> INCOMING edge: wake SpringBoard loudly */
        if (ci2.state == SP_CALL_INCOMING && prev_state != SP_CALL_INCOMING) {
            reset_call_controls(a);
            a->capture_call = 0;
            publish(a, 1);
        }
        /* ENDED -> IDLE once the UI has had time to show "call ended" */
        if (ci2.state == SP_CALL_ENDED) {
            if (!a->ended_clear_at)
                a->ended_clear_at = sp_now_ms() + 2500;
            else if (sp_now_ms() >= a->ended_clear_at) {
                a->ended_clear_at = 0;
                sp_ua_clear_ended(a->ua);             /* publishes IDLE through hook_changed */
                sp_ua_call(a->ua, &ci2);
            }
        } else {
            a->ended_clear_at = 0;
        }
        g_prev_call_state = ci2.state;

        if (g_term && !a->quit_at) {
            sp_log("SIGTERM: unregistering before exit");
            if (sp_ua_busy(a->ua))
                sp_ua_hangup(a->ua);
            sp_ua_unregister(a->ua);
            a->quit_at = sp_now_ms() + 3000;   /* keep looping so the 401 to Expires: 0 gets answered */
        }
        if (a->quit_at && sp_now_ms() >= a->quit_at) {
            stop_audio(a);
            unlink(SP_SOCK_PATH);
            exit(0);
        }
    }
    return 0;
}

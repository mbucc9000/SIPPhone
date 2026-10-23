#include "sp_ua.h"
#include "sp_sip.h"
#include "sp_sdp.h"
#include "sp_srtp.h"
#include "sp_md5.h"
#include "sp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define T1 500
#define T2 4000
#define TX_TIMEOUT (64 * T1)
#define RING_TIMEOUT (180 * 1000)
#define MAX_TX 12
#define MAX_RC 16
#define MAX_ROUTES 8
#define DTMF_PT 101
#define ALLOW_HDR "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY, INFO, MESSAGE\r\n"

enum { TXK_REGISTER = 1, TXK_INVITE, TXK_REINVITE, TXK_BYE, TXK_CANCEL };

typedef struct {
    int      used;
    int      kind;
    char     branch[48];
    char     method[16];
    uint32_t cseq;
    char     call_id[96];
    char    *msg;
    size_t   len;
    int64_t  next_rt;
    int      interval;
    int64_t  deadline;
    int      prov;
    int      cancel_pending;   /* INVITE: hang up arrived before any 1xx */
    int      completed;        /* INVITE got a non-2xx final: absorbing retransmissions (Timer D) */
    char    *ack;              /* the ACK we sent for that final, re-sent on each retransmission */
} sp_tx;

typedef struct {
    int     used;
    char    key[160];
    char   *resp;
    size_t  len;
    int64_t expire;
} sp_rc;

typedef struct {
    int      id, state, incoming;
    char     call_id[96];
    char     ltag[32], rtag[128];
    char     local_hv[320], remote_hv[320];   /* name-addr without tags */
    char     remote_target[320];
    char     routes[MAX_ROUTES][320];
    int      nroutes;
    uint32_t lcseq, rcseq;
    uint32_t inv_cseq;
    int      auth_tries;
    char    *ack_msg;          /* our ACK for the 2xx (re-sent on 2xx retransmission) */
    sp_msg   inv;              /* incoming INVITE being answered */
    int      has_inv;
    char    *fin_msg;          /* final INVITE response waiting for ACK (UDP) */
    int64_t  fin_next, fin_deadline;
    int      fin_interval, fin_2xx;
    uint32_t fin_cseq;
    int      late_offer;
    sp_sdp   rsdp;
    int      have_rsdp;
    int      pt, dtmf_pt, local_hold, media_on;
    int      secure;                        /* SRTP (SDES) negotiated for this call */
    int      crypto_tag;                    /* the a=crypto tag we send */
    uint8_t  tx_key[SP_SDES_KEYING];        /* our inline key: encrypts what we send */
    uint8_t  rx_key[SP_SDES_KEYING];        /* peer's inline key: decrypts what we receive */
    int      have_rx_key;
    uint32_t sess_id, sdp_ver;
    char     number[64], display[96], reason[96];
    int      status, answered;
    long     connected_at;
    int64_t  ring_deadline;    /* incoming: give up ringing if the CANCEL got lost */
} sp_call;

struct sp_ua {
    sp_hooks h;
    sp_cfg   cfg;
    int      configured;
    char     local_ip[64];
    int      local_port;
    char     pub_ip[64];
    int      pub_port;
    char     pub_text[96];
    int      rtp_port;
    struct {
        int      state;
        char     detail[96];
        char     call_id[96];
        char     tag[32];
        uint32_t cseq;
        int      granted;
        int64_t  refresh_at, retry_at;
        int      auth_tries, backoff;
        int      unregistering;
        int      recontact_done;
        char     contact[320];
    } reg;
    uint32_t nc;
    char     nc_nonce[256];
    sp_tx    tx[MAX_TX];
    sp_rc    rc[MAX_RC];
    sp_call  c;
    int      next_id;
};

/* ------------------------------------------------------------------ helpers */

static void changed(sp_ua *ua)
{
    if (ua->h.changed)
        ua->h.changed(ua->h.ctx);
}

static int is_tcp(const sp_ua *ua)
{
    return ua->cfg.transport != SP_TP_UDP;   /* TCP and TLS both use stream framing */
}

/* SIP transport token for Via, and the Contact ;transport= param */
static const char *tp_via(const sp_ua *ua)
{
    return ua->cfg.transport == SP_TP_TLS ? "TLS" : ua->cfg.transport == SP_TP_TCP ? "TCP" : "UDP";
}

static const char *tp_contact(const sp_ua *ua)
{
    return ua->cfg.transport == SP_TP_TLS ? ";transport=tls"
         : ua->cfg.transport == SP_TP_TCP ? ";transport=tcp" : "";
}

static void new_branch(char out[48])
{
    char r[17];
    sp_rand_hex(r, 16);
    snprintf(out, 48, "z9hG4bK%s", r);
}

static void new_tag(char out[32])
{
    sp_rand_hex(out, 10);
}

static void raw_send(sp_ua *ua, const char *s, size_t n)
{
    sp_log_block(">>>", s, n);
    if (ua->h.send)
        ua->h.send(ua->h.ctx, s, n);
}

static const char *contact_host(const sp_ua *ua, int *port)
{
    if (ua->pub_ip[0]) {
        *port = ua->pub_port;
        return ua->pub_ip;
    }
    *port = ua->local_port;
    return ua->local_ip[0] ? ua->local_ip : "0.0.0.0";
}

static void contact_hv(const sp_ua *ua, char *out, size_t n)
{
    int port;
    const char *host = contact_host(ua, &port);
    snprintf(out, n, "<sip:%s@%s:%d%s>", ua->cfg.user, host, port,
             tp_contact(ua));
}

static void aor(const sp_ua *ua, char *out, size_t n)
{
    snprintf(out, n, "sip:%s@%s", ua->cfg.user, ua->cfg.server);
}

static void name_addr(const sp_ua *ua, const char *uri, char *out, size_t n)
{
    if (ua->cfg.display[0])
        snprintf(out, n, "\"%s\" <%s>", ua->cfg.display, uri);
    else
        snprintf(out, n, "<%s>", uri);
}

/* removes ;tag=... from a From/To value */
static void strip_tag(const char *hv, char *out, size_t n, char *tag, size_t tn)
{
    sp_strlcpy(out, hv, n);
    if (tag && tn)
        tag[0] = 0;
    const char *gt = strchr(out, '>');
    char *p = (char *)(gt ? gt : out);
    while ((p = strchr(p, ';'))) {
        if (sp_strncaseeq(p + 1, "tag=", 4)) {
            char *e = p + 5;
            size_t l = strcspn(e, ";");
            if (tag && tn) {
                size_t k = l < tn - 1 ? l : tn - 1;
                memcpy(tag, e, k);
                tag[k] = 0;
            }
            memmove(p, e + l, strlen(e + l) + 1);
            continue;
        }
        p++;
    }
}

/* ------------------------------------------------------------ transactions */

static void tx_free(sp_tx *t)
{
    free(t->msg);
    free(t->ack);
    memset(t, 0, sizeof *t);
}

static sp_tx *tx_new(sp_ua *ua)
{
    sp_tx *oldest = &ua->tx[0];
    for (int i = 0; i < MAX_TX; i++) {
        if (!ua->tx[i].used)
            return &ua->tx[i];
        if (ua->tx[i].deadline < oldest->deadline)
            oldest = &ua->tx[i];
    }
    sp_log("tx table full, dropping %s", oldest->method);
    tx_free(oldest);
    return oldest;
}

static sp_tx *tx_start(sp_ua *ua, int kind, const char *method, uint32_t cseq,
                       const char *branch, const char *call_id, char *msg)
{
    sp_tx *t = tx_new(ua);
    t->used = 1;
    t->kind = kind;
    sp_strlcpy(t->method, method, sizeof t->method);
    t->cseq = cseq;
    sp_strlcpy(t->branch, branch, sizeof t->branch);
    sp_strlcpy(t->call_id, call_id, sizeof t->call_id);
    t->msg = msg;
    t->len = strlen(msg);
    int64_t now = sp_now_ms();
    t->deadline = now + TX_TIMEOUT;
    if (!is_tcp(ua)) {
        t->interval = T1;
        t->next_rt = now + T1;
    }
    raw_send(ua, t->msg, t->len);
    return t;
}

static sp_tx *tx_find(sp_ua *ua, const char *branch, const char *method)
{
    for (int i = 0; i < MAX_TX; i++)
        if (ua->tx[i].used && strcmp(ua->tx[i].branch, branch) == 0 &&
            sp_strcaseeq(ua->tx[i].method, method))
            return &ua->tx[i];
    return NULL;
}

static sp_tx *tx_find_invite(sp_ua *ua, const char *call_id)
{
    for (int i = 0; i < MAX_TX; i++)
        if (ua->tx[i].used && ua->tx[i].kind == TXK_INVITE && !ua->tx[i].completed &&
            strcmp(ua->tx[i].call_id, call_id) == 0)
            return &ua->tx[i];
    return NULL;
}

/* -------------------------------------------------------- message building */

static char *build_req(sp_ua *ua, const char *method, const char *ruri, const char *branch,
                       const char *from, const char *to, const char *call_id, uint32_t cseq,
                       char routes[][320], int nroutes, int with_contact, const char *extra,
                       const char *ctype, const char *body)
{
    sp_buf b;
    sp_buf_init(&b);
    sp_buf_printf(&b, "%s %s SIP/2.0\r\n", method, ruri);
    sp_buf_printf(&b, "Via: SIP/2.0/%s %s:%d;branch=%s;rport\r\n", tp_via(ua),
                  ua->local_ip[0] ? ua->local_ip : "0.0.0.0", ua->local_port, branch);
    sp_buf_puts(&b, "Max-Forwards: 70\r\n");
    for (int i = 0; i < nroutes; i++)
        sp_buf_printf(&b, "Route: %s\r\n", routes[i]);
    sp_buf_printf(&b, "From: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %u %s\r\n", from, to, call_id,
                  cseq, method);
    if (with_contact) {
        char ct[320];
        contact_hv(ua, ct, sizeof ct);
        sp_buf_printf(&b, "Contact: %s\r\n", ct);
    }
    if (extra)
        sp_buf_puts(&b, extra);
    sp_buf_printf(&b, "User-Agent: %s\r\n", ua->cfg.user_agent[0] ? ua->cfg.user_agent : "SIPPhone");
    if (body && *body) {
        sp_buf_printf(&b, "Content-Type: %s\r\nContent-Length: %u\r\n\r\n", ctype,
                      (unsigned)strlen(body));
        sp_buf_puts(&b, body);
    } else {
        sp_buf_puts(&b, "Content-Length: 0\r\n\r\n");
    }
    return sp_buf_take(&b);
}

static char *build_resp(sp_ua *ua, const sp_msg *req, int status, const char *reason,
                        const char *to_tag, int with_contact, const char *extra,
                        const char *ctype, const char *body)
{
    sp_buf b;
    sp_buf_init(&b);
    sp_buf_printf(&b, "SIP/2.0 %d %s\r\n", status, reason);
    const char *vias[16];
    int nv = sp_hdr_all(req, "Via", vias, 16);
    for (int i = 0; i < nv; i++)
        sp_buf_printf(&b, "Via: %s\r\n", vias[i]);
    const char *rr[MAX_ROUTES];
    if (status > 100 && status < 300) {
        int nrr = sp_hdr_all(req, "Record-Route", rr, MAX_ROUTES);
        for (int i = 0; i < nrr; i++)
            sp_buf_printf(&b, "Record-Route: %s\r\n", rr[i]);
    }
    const char *from = sp_hdr_get(req, "From"), *to = sp_hdr_get(req, "To");
    sp_buf_printf(&b, "From: %s\r\n", from ? from : "");
    if (to && to_tag && to_tag[0] && status > 100 && !sp_param(to, "tag", NULL, 0))
        sp_buf_printf(&b, "To: %s;tag=%s\r\n", to, to_tag);
    else
        sp_buf_printf(&b, "To: %s\r\n", to ? to : "");
    const char *cid = sp_hdr_get(req, "Call-ID"), *cs = sp_hdr_get(req, "CSeq");
    sp_buf_printf(&b, "Call-ID: %s\r\nCSeq: %s\r\n", cid ? cid : "", cs ? cs : "");
    if (with_contact) {
        char ct[320];
        contact_hv(ua, ct, sizeof ct);
        sp_buf_printf(&b, "Contact: %s\r\n", ct);
    }
    if (extra)
        sp_buf_puts(&b, extra);
    sp_buf_printf(&b, "User-Agent: %s\r\n", ua->cfg.user_agent[0] ? ua->cfg.user_agent : "SIPPhone");
    if (body && *body) {
        sp_buf_printf(&b, "Content-Type: %s\r\nContent-Length: %u\r\n\r\n", ctype,
                      (unsigned)strlen(body));
        sp_buf_puts(&b, body);
    } else {
        sp_buf_puts(&b, "Content-Length: 0\r\n\r\n");
    }
    return sp_buf_take(&b);
}

/* response cache: lets a retransmitted request get the same answer again */
static void rc_key(const sp_msg *req, char *out, size_t n)
{
    char br[64];
    sp_top_branch(req, br, sizeof br);
    const char *cs = sp_hdr_get(req, "CSeq");
    const char *cid = sp_hdr_get(req, "Call-ID");
    snprintf(out, n, "%s|%s|%.40s", br, cs ? cs : "", cid ? cid : "");
}

static void rc_store(sp_ua *ua, const sp_msg *req, const char *resp)
{
    char key[160];
    rc_key(req, key, sizeof key);
    sp_rc *slot = NULL, *oldest = &ua->rc[0];
    for (int i = 0; i < MAX_RC; i++) {
        if (ua->rc[i].used && strcmp(ua->rc[i].key, key) == 0) {
            slot = &ua->rc[i];
            break;
        }
        if (!ua->rc[i].used && !slot)
            slot = &ua->rc[i];
        if (ua->rc[i].expire < oldest->expire)
            oldest = &ua->rc[i];
    }
    if (!slot)
        slot = oldest;
    free(slot->resp);
    slot->used = 1;
    sp_strlcpy(slot->key, key, sizeof slot->key);
    slot->resp = sp_strdup_n(resp, strlen(resp));
    slot->len = strlen(resp);
    slot->expire = sp_now_ms() + TX_TIMEOUT;
}

static int rc_resend(sp_ua *ua, const sp_msg *req)
{
    char key[160];
    rc_key(req, key, sizeof key);
    int64_t now = sp_now_ms();
    for (int i = 0; i < MAX_RC; i++) {
        sp_rc *r = &ua->rc[i];
        if (!r->used)
            continue;
        if (r->expire < now) {
            free(r->resp);
            memset(r, 0, sizeof *r);
            continue;
        }
        if (strcmp(r->key, key) == 0) {
            sp_log("retransmitted %s, repeating our answer", req->method);
            raw_send(ua, r->resp, r->len);
            return 1;
        }
    }
    return 0;
}

static void send_resp(sp_ua *ua, const sp_msg *req, int status, const char *reason,
                      const char *to_tag, int with_contact, const char *extra,
                      const char *ctype, const char *body)
{
    char *r = build_resp(ua, req, status, reason, to_tag, with_contact, extra, ctype, body);
    raw_send(ua, r, strlen(r));
    rc_store(ua, req, r);
    free(r);
}

/* ------------------------------------------------------------------ media */

static void media_apply(sp_ua *ua)
{
    sp_call *c = &ua->c;
    if (!c->have_rsdp || c->pt < 0 || c->rsdp.port <= 0)
        return;
    if (c->secure && !c->have_rx_key)       /* fail-closed: never send media in the clear */
        return;
    int dir = sp_sdp_answer_dir(c->rsdp.dir, c->local_hold);
    if (ua->h.media) {
        sp_media_info m;
        memset(&m, 0, sizeof m);
        m.on = 1;
        m.ip = c->rsdp.ip;
        m.port = c->rsdp.port;
        m.pt = c->pt;
        m.dtmf_pt = c->dtmf_pt;
        m.dir = dir;
        m.secure = c->secure;
        m.tx_key = c->secure ? c->tx_key : NULL;
        m.rx_key = c->secure ? c->rx_key : NULL;
        ua->h.media(ua->h.ctx, &m);
    }
    c->media_on = 1;
}

static void media_stop(sp_ua *ua)
{
    sp_call *c = &ua->c;
    if (ua->h.tone)
        ua->h.tone(ua->h.ctx, SP_TONE_NONE);
    if (c->media_on && ua->h.media) {
        sp_media_info m;
        memset(&m, 0, sizeof m);
        m.pt = m.dtmf_pt = -1;
        ua->h.media(ua->h.ctx, &m);     /* on = 0 */
    }
    c->media_on = 0;
}

static void local_sdp(sp_ua *ua, char *out, size_t n, int answer)
{
    sp_call *c = &ua->c;
    int port;
    const char *ip = contact_host(ua, &port);
    const uint8_t *key = c->secure ? c->tx_key : NULL;
    if (answer && c->pt >= 0) {
        int pts[1] = { c->pt };
        sp_sdp_build(out, n, ip, ua->rtp_port, c->sess_id, c->sdp_ver, pts, 1, c->rsdp.dtmf_pt,
                     sp_sdp_answer_dir(c->rsdp.dir, c->local_hold), key, c->crypto_tag);
    } else {
        int pts[2] = { 0, 8 };
        sp_sdp_build(out, n, ip, ua->rtp_port, c->sess_id, c->sdp_ver, pts, 2, DTMF_PT,
                     c->local_hold ? SP_DIR_SENDONLY : SP_DIR_SENDRECV, key, c->crypto_tag);
    }
}

/* takes remote SDP from a message body; 0 ok, -1 no SDP, -2 no usable codec */
static int take_sdp(sp_ua *ua, const sp_msg *m)
{
    sp_call *c = &ua->c;
    if (!m->blen)
        return -1;
    const char *ct = sp_hdr_get(m, "Content-Type");
    if (ct && !sp_strncaseeq(ct, "application/sdp", 15))
        return -1;
    sp_sdp s;
    if (sp_sdp_parse(m->body, m->blen, &s) != 0)
        return -1;
    int pt = sp_sdp_choose(&s);
    if (pt < 0)
        return -2;
    if (c->secure) {
        /* fail-closed: an encrypted call must carry SRTP keying, never plaintext */
        if (!s.savp || !s.have_crypto) {
            sp_log("remote offered no SRTP on a secure call: rejecting");
            return -2;
        }
        memcpy(c->rx_key, s.crypto_key, SP_SDES_KEYING);
        c->have_rx_key = 1;
    }
    c->rsdp = s;
    c->have_rsdp = 1;
    c->pt = pt;
    c->dtmf_pt = s.dtmf_pt;
    sp_log("remote media %s:%d pt %d dtmf %d %s%s", s.ip, s.port, pt, s.dtmf_pt,
           sp_sdp_dir_name(s.dir), c->secure ? " [SRTP]" : "");
    return 0;
}

/* ------------------------------------------------------------------ calls */

static void call_reset(sp_ua *ua)
{
    sp_call *c = &ua->c;
    free(c->ack_msg);
    free(c->fin_msg);
    if (c->has_inv)
        sp_msg_free(&c->inv);
    memset(c, 0, sizeof *c);
    c->pt = c->dtmf_pt = -1;
}

/* Per-call SRTP state: our own key for what we send; the peer's comes from its SDP. */
static void call_secure_setup(sp_ua *ua)
{
    sp_call *c = &ua->c;
    c->secure = ua->cfg.secure ? 1 : 0;
    c->have_rx_key = 0;
    if (c->secure) {
        sp_rand_bytes(c->tx_key, SP_SDES_KEYING);
        c->crypto_tag = 1;
    }
}

static void call_end(sp_ua *ua, const char *reason, int status)
{
    sp_call *c = &ua->c;
    media_stop(ua);
    c->state = SP_CALL_ENDED;
    sp_strlcpy(c->reason, reason, sizeof c->reason);
    c->status = status;
    sp_log("call %d ended: %s (%d)", c->id, reason, status);
    changed(ua);
}

static const char *fail_reason(int st)
{
    switch (st) {
    case 486: case 600: return "Busy";
    case 404: case 604: return "Number not found";
    case 484: return "Incomplete number";
    case 480: return "Unavailable";
    case 402: return "Out of credit";
    case 403: return "Call rejected";
    case 401: case 407: return "Authentication failed";
    case 408: return "No answer";
    case 487: return "Call ended";
    case 488: case 606: return "Call failed (audio)";
    case 503: return "Service unavailable";
    case 603: return "Declined";
    default: return "Call failed";
    }
}

static char *build_indialog(sp_ua *ua, const char *method, uint32_t cseq, const char *branch,
                            int with_contact, const char *extra, const char *ctype,
                            const char *body)
{
    sp_call *c = &ua->c;
    char from[400], to[400];
    snprintf(from, sizeof from, "%s;tag=%s", c->local_hv, c->ltag);
    if (c->rtag[0])
        snprintf(to, sizeof to, "%s;tag=%s", c->remote_hv, c->rtag);
    else
        sp_strlcpy(to, c->remote_hv, sizeof to);
    return build_req(ua, method, c->remote_target, branch, from, to, c->call_id, cseq, c->routes,
                     c->nroutes, with_contact, extra, ctype, body);
}

static void send_bye(sp_ua *ua)
{
    sp_call *c = &ua->c;
    char br[48];
    new_branch(br);
    c->lcseq++;
    char *m = build_indialog(ua, "BYE", c->lcseq, br, 0, NULL, NULL, NULL);
    tx_start(ua, TXK_BYE, "BYE", c->lcseq, br, c->call_id, m);
}

static void send_invite(sp_ua *ua, const char *auth_line)
{
    sp_call *c = &ua->c;
    char from[400], sdp[1024], extra[2048], br[48];
    snprintf(from, sizeof from, "%s;tag=%s", c->local_hv, c->ltag);
    new_branch(br);
    c->inv_cseq = c->lcseq;
    local_sdp(ua, sdp, sizeof sdp, 0);
    snprintf(extra, sizeof extra, "%s%s%s", ALLOW_HDR, auth_line ? auth_line : "",
             auth_line ? "\r\n" : "");
    char *m = build_req(ua, "INVITE", c->remote_target, br, from, c->remote_hv, c->call_id,
                        c->inv_cseq, NULL, 0, 1, extra, "application/sdp", sdp);
    tx_start(ua, TXK_INVITE, "INVITE", c->inv_cseq, br, c->call_id, m);
}

/* CANCEL is built from the INVITE it cancels (same Via, R-URI, From, To, Call-ID, Route). */
static void send_cancel(sp_ua *ua, sp_tx *t)
{
    sp_msg inv;
    if (sp_msg_parse(&inv, t->msg, t->len) != 0)
        return;
    sp_buf b;
    sp_buf_init(&b);
    sp_buf_printf(&b, "CANCEL %s SIP/2.0\r\n", inv.ruri);
    const char *via = sp_hdr_get(&inv, "Via");
    sp_buf_printf(&b, "Via: %s\r\nMax-Forwards: 70\r\n", via ? via : "");
    const char *rt[MAX_ROUTES];
    int nr = sp_hdr_all(&inv, "Route", rt, MAX_ROUTES);
    for (int i = 0; i < nr; i++)
        sp_buf_printf(&b, "Route: %s\r\n", rt[i]);
    sp_buf_printf(&b, "From: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %u CANCEL\r\n",
                  sp_hdr_get(&inv, "From"), sp_hdr_get(&inv, "To"), sp_hdr_get(&inv, "Call-ID"),
                  t->cseq);
    sp_buf_printf(&b, "User-Agent: %s\r\nContent-Length: 0\r\n\r\n",
                  ua->cfg.user_agent[0] ? ua->cfg.user_agent : "SIPPhone");
    char *m = sp_buf_take(&b);
    char cid[96], br[48];
    sp_strlcpy(cid, t->call_id, sizeof cid);
    sp_strlcpy(br, t->branch, sizeof br);
    uint32_t cs = t->cseq;
    sp_msg_free(&inv);
    t->cancel_pending = 0;
    tx_start(ua, TXK_CANCEL, "CANCEL", cs, br, cid, m);
}

/* ACK for a non-2xx final response: hop-by-hop, same branch as the INVITE */
static void send_ack_non2xx(sp_ua *ua, sp_tx *t, const sp_msg *resp)
{
    sp_msg inv;
    if (sp_msg_parse(&inv, t->msg, t->len) != 0)
        return;
    sp_buf b;
    sp_buf_init(&b);
    sp_buf_printf(&b, "ACK %s SIP/2.0\r\n", inv.ruri);
    const char *via = sp_hdr_get(&inv, "Via");
    sp_buf_printf(&b, "Via: %s\r\nMax-Forwards: 70\r\n", via ? via : "");
    const char *rt[MAX_ROUTES];
    int nr = sp_hdr_all(&inv, "Route", rt, MAX_ROUTES);
    for (int i = 0; i < nr; i++)
        sp_buf_printf(&b, "Route: %s\r\n", rt[i]);
    const char *to = sp_hdr_get(resp, "To");
    sp_buf_printf(&b, "From: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %u ACK\r\nContent-Length: 0\r\n\r\n",
                  sp_hdr_get(&inv, "From"), to ? to : sp_hdr_get(&inv, "To"),
                  sp_hdr_get(&inv, "Call-ID"), t->cseq);
    free(t->ack);
    t->ack = sp_buf_take(&b);
    raw_send(ua, t->ack, strlen(t->ack));
    sp_msg_free(&inv);
}

/* RFC 3261 17.1.1.2: after a non-2xx final the client INVITE transaction
   stays "Completed" for 32 s over UDP and answers every retransmission of
   that final with the same ACK. Over TCP nothing is retransmitted. */
static void tx_complete(sp_ua *ua, sp_tx *t)
{
    if (is_tcp(ua)) {
        tx_free(t);
        return;
    }
    t->completed = 1;
    t->next_rt = 0;
    t->deadline = sp_now_ms() + TX_TIMEOUT;
}

static int routes_from(const sp_msg *m, char routes[][320], int reverse)
{
    const char *rr[MAX_ROUTES];
    char tmp[MAX_ROUTES * 2][320];
    int n = 0;
    int nh = sp_hdr_all(m, "Record-Route", rr, MAX_ROUTES);
    for (int i = 0; i < nh && n < MAX_ROUTES * 2; i++)
        n += sp_split_commas(rr[i], tmp + n, MAX_ROUTES * 2 - n);
    if (n > MAX_ROUTES)
        n = MAX_ROUTES;
    for (int i = 0; i < n; i++)
        sp_strlcpy(routes[i], tmp[reverse ? n - 1 - i : i], 320);
    return n;
}

/* A 2xx arrived for an INVITE whose call we already gave up on: ACK it, then BYE. */
static void ack_and_bye_stray(sp_ua *ua, sp_tx *t, const sp_msg *resp)
{
    sp_msg inv;
    if (sp_msg_parse(&inv, t->msg, t->len) != 0)
        return;
    char target[320], routes[MAX_ROUTES][320], br[48], from[400], to[400], cid[96];
    sp_hv_uri(sp_hdr_get(resp, "Contact"), target, sizeof target);
    if (!target[0])
        sp_strlcpy(target, inv.ruri, sizeof target);
    int nr = routes_from(resp, routes, 1);
    sp_strlcpy(from, sp_hdr_get(&inv, "From"), sizeof from);
    const char *rto = sp_hdr_get(resp, "To");
    sp_strlcpy(to, rto ? rto : "", sizeof to);
    sp_strlcpy(cid, t->call_id, sizeof cid);
    uint32_t cs = t->cseq;
    sp_msg_free(&inv);

    new_branch(br);
    char *ack = build_req(ua, "ACK", target, br, from, to, cid, cs, routes, nr, 0, NULL, NULL, NULL);
    raw_send(ua, ack, strlen(ack));
    free(ack);
    new_branch(br);
    char *bye = build_req(ua, "BYE", target, br, from, to, cid, cs + 1, routes, nr, 0, NULL, NULL, NULL);
    tx_start(ua, TXK_BYE, "BYE", cs + 1, br, cid, bye);
}

/* final INVITE responses we send are repeated over UDP until the ACK shows up */
static void fin_start(sp_ua *ua, const char *resp, uint32_t cseq, int is2xx)
{
    sp_call *c = &ua->c;
    free(c->fin_msg);
    c->fin_msg = NULL;
    if (is_tcp(ua) && !is2xx)
        return;
    c->fin_msg = sp_strdup_n(resp, strlen(resp));
    c->fin_cseq = cseq;
    c->fin_2xx = is2xx;
    c->fin_interval = T1;
    int64_t now = sp_now_ms();
    c->fin_next = is_tcp(ua) ? 0 : now + T1;
    c->fin_deadline = now + TX_TIMEOUT;
}

static void send_final(sp_ua *ua, const sp_msg *req, int status, const char *reason,
                       const char *extra, const char *body)
{
    sp_call *c = &ua->c;
    char *r = build_resp(ua, req, status, reason, c->ltag, status < 300, extra,
                         "application/sdp", body);
    raw_send(ua, r, strlen(r));
    rc_store(ua, req, r);
    uint32_t cs = 0;
    sp_cseq(req, &cs, NULL, 0);
    fin_start(ua, r, cs, status < 300);
    free(r);
}

static void on_invite_resp(sp_ua *ua, sp_tx *t, const sp_msg *m)
{
    sp_call *c = &ua->c;
    int st = m->status;
    int ours = !c->incoming && c->state != SP_CALL_IDLE && strcmp(t->call_id, c->call_id) == 0;
    int64_t now = sp_now_ms();

    if (st < 200) {
        if (!t->prov) {
            t->prov = 1;
            t->next_rt = 0;
            t->deadline = now + RING_TIMEOUT;
        }
        if (t->cancel_pending) {
            send_cancel(ua, t);
            return;
        }
        if (!ours || c->state == SP_CALL_ENDED || st == 100)
            return;
        char tag[128];
        if (sp_param(sp_hdr_get(m, "To"), "tag", tag, sizeof tag) && tag[0])
            sp_strlcpy(c->rtag, tag, sizeof c->rtag);
        const char *ct = sp_hdr_get(m, "Contact");
        if (ct)
            sp_hv_uri(ct, c->remote_target, sizeof c->remote_target);
        int had_media = c->media_on;
        if (take_sdp(ua, m) == 0)
            media_apply(ua);
        if (c->state == SP_CALL_CALLING || !had_media) {
            c->state = SP_CALL_RINGING;
            if (ua->h.tone)
                ua->h.tone(ua->h.ctx, SP_TONE_RINGBACK);
            changed(ua);
        }
        return;
    }

    if (st < 300) {
        if (!ours || c->state == SP_CALL_ENDED) {
            sp_log("2xx for a call we already ended: ACK + BYE");
            ack_and_bye_stray(ua, t, m);
            tx_free(t);
            return;
        }
        char tag[128];
        if (sp_param(sp_hdr_get(m, "To"), "tag", tag, sizeof tag))
            sp_strlcpy(c->rtag, tag, sizeof c->rtag);
        const char *ct = sp_hdr_get(m, "Contact");
        if (ct)
            sp_hv_uri(ct, c->remote_target, sizeof c->remote_target);
        c->nroutes = routes_from(m, c->routes, 1);
        take_sdp(ua, m);
        char br[48];
        new_branch(br);
        free(c->ack_msg);
        c->ack_msg = build_indialog(ua, "ACK", c->inv_cseq, br, 0, NULL, NULL, NULL);
        raw_send(ua, c->ack_msg, strlen(c->ack_msg));
        tx_free(t);
        if (!c->have_rsdp) {
            send_bye(ua);
            call_end(ua, "Call failed (no audio)", 488);
            return;
        }
        c->state = SP_CALL_ACTIVE;
        c->connected_at = (long)time(NULL);
        if (ua->h.tone)
            ua->h.tone(ua->h.ctx, SP_TONE_NONE);
        media_apply(ua);
        changed(ua);
        return;
    }

    send_ack_non2xx(ua, t, m);
    if (!ours || c->state == SP_CALL_ENDED) {
        tx_complete(ua, t);
        return;
    }
    if ((st == 401 || st == 407) && c->auth_tries < 2) {
        const char *chv = sp_hdr_get(m, st == 401 ? "WWW-Authenticate" : "Proxy-Authenticate");
        sp_challenge ch;
        if (chv && sp_challenge_parse(chv, &ch) == 0) {
            c->auth_tries++;
            if (strcmp(ch.nonce, ua->nc_nonce) != 0) {
                ua->nc = 0;
                sp_strlcpy(ua->nc_nonce, ch.nonce, sizeof ua->nc_nonce);
            }
            char line[1500], dig[1400];
            const char *au = ua->cfg.auth_user[0] ? ua->cfg.auth_user : ua->cfg.user;
            if (sp_digest_build(dig, sizeof dig, &ch, "INVITE", c->remote_target, au,
                                ua->cfg.password, &ua->nc) == 0) {
                snprintf(line, sizeof line, "%s: %s",
                         st == 401 ? "Authorization" : "Proxy-Authorization", dig);
                int cancel = t->cancel_pending;
                tx_complete(ua, t);
                c->lcseq++;
                send_invite(ua, line);
                if (cancel) {
                    sp_tx *nt = tx_find_invite(ua, c->call_id);
                    if (nt)
                        nt->cancel_pending = 1;
                }
                return;
            }
        }
    }
    tx_complete(ua, t);
    call_end(ua, fail_reason(st), st);
}

static void on_reinvite_resp(sp_ua *ua, sp_tx *t, const sp_msg *m)
{
    sp_call *c = &ua->c;
    if (m->status < 200)
        return;
    int ours = strcmp(t->call_id, c->call_id) == 0 && c->state == SP_CALL_ACTIVE;
    if (m->status < 300) {
        char br[48];
        new_branch(br);
        if (ours) {
            char *ack = build_indialog(ua, "ACK", t->cseq, br, 0, NULL, NULL, NULL);
            raw_send(ua, ack, strlen(ack));
            free(ack);
            if (take_sdp(ua, m) == 0)
                media_apply(ua);
        }
    } else {
        send_ack_non2xx(ua, t, m);
        sp_log("re-INVITE refused: %d", m->status);
        tx_complete(ua, t);
        return;
    }
    tx_free(t);
}

/* ------------------------------------------------------------ registration */

static void reg_send(sp_ua *ua, int expires, const char *auth_line)
{
    char ruri[160], uri[200], from[400], to[300], br[48], extra[2048];
    snprintf(ruri, sizeof ruri, "sip:%s", ua->cfg.server);
    aor(ua, uri, sizeof uri);
    char na[300];
    name_addr(ua, uri, na, sizeof na);
    snprintf(from, sizeof from, "%s;tag=%s", na, ua->reg.tag);
    snprintf(to, sizeof to, "<%s>", uri);
    for (int i = 0; i < MAX_TX; i++)
        if (ua->tx[i].used && ua->tx[i].kind == TXK_REGISTER)
            tx_free(&ua->tx[i]);
    ua->reg.cseq++;
    new_branch(br);
    snprintf(extra, sizeof extra, "Expires: %d\r\n%s%s%s", expires, ALLOW_HDR,
             auth_line ? auth_line : "", auth_line ? "\r\n" : "");
    contact_hv(ua, ua->reg.contact, sizeof ua->reg.contact);
    char *m = build_req(ua, "REGISTER", ruri, br, from, to, ua->reg.call_id, ua->reg.cseq, NULL, 0,
                        1, extra, NULL, NULL);
    ua->reg.unregistering = expires == 0;
    ua->reg.refresh_at = ua->reg.retry_at = 0;
    if (ua->reg.state == SP_REG_OFF && expires) {
        ua->reg.state = SP_REG_TRYING;
        sp_strlcpy(ua->reg.detail, "Registering", sizeof ua->reg.detail);
        changed(ua);
    }
    tx_start(ua, TXK_REGISTER, "REGISTER", ua->reg.cseq, br, ua->reg.call_id, m);
}

static void reg_fail(sp_ua *ua, int st, const char *why)
{
    if (!ua->cfg.do_register || ua->reg.unregistering) {
        ua->reg.state = SP_REG_OFF;
        ua->reg.refresh_at = ua->reg.retry_at = 0;
        ua->reg.unregistering = 0;
        sp_strlcpy(ua->reg.detail, "Off", sizeof ua->reg.detail);
        changed(ua);
        return;
    }
    ua->reg.state = SP_REG_FAILED;
    if (why)
        sp_strlcpy(ua->reg.detail, why, sizeof ua->reg.detail);
    else if (st == 401 || st == 407)
        sp_strlcpy(ua->reg.detail, "Wrong username or password", sizeof ua->reg.detail);
    else if (st == 403)
        sp_strlcpy(ua->reg.detail, "Forbidden: check username/password", sizeof ua->reg.detail);
    else if (st == 404)
        sp_strlcpy(ua->reg.detail, "Unknown username", sizeof ua->reg.detail);
    else if (st == 408)
        sp_strlcpy(ua->reg.detail, "No response from server", sizeof ua->reg.detail);
    else
        snprintf(ua->reg.detail, sizeof ua->reg.detail, "Server said %d", st);
    ua->reg.backoff = ua->reg.backoff ? ua->reg.backoff * 2 : 30;
    if (ua->reg.backoff > 300)
        ua->reg.backoff = 300;
    ua->reg.retry_at = sp_now_ms() + (int64_t)ua->reg.backoff * 1000;
    ua->reg.auth_tries = 0;
    sp_log("registration failed: %s (retry in %ds)", ua->reg.detail, ua->reg.backoff);
    changed(ua);
}

static int granted_expires(sp_ua *ua, const sp_msg *m)
{
    const char *cts[16];
    int n = sp_hdr_all(m, "Contact", cts, 16);
    char ours[320];
    sp_hv_uri(ua->reg.contact, ours, sizeof ours);
    for (int i = 0; i < n; i++) {
        char list[8][320];
        int k = sp_split_commas(cts[i], list, 8);
        for (int j = 0; j < k; j++) {
            char u[320], e[16];
            sp_hv_uri(list[j], u, sizeof u);
            if (sp_strcaseeq(u, ours) && sp_param(list[j], "expires", e, sizeof e) && e[0])
                return atoi(e);
        }
    }
    const char *ex = sp_hdr_get(m, "Expires");
    if (ex)
        return atoi(ex);
    return ua->cfg.expires;
}

static void on_register_resp(sp_ua *ua, sp_tx *t, const sp_msg *m)
{
    int st = m->status;
    if (st < 200)
        return;
    tx_free(t);
    if (st < 300) {
        if (ua->reg.unregistering) {
            ua->reg.state = SP_REG_OFF;
            sp_strlcpy(ua->reg.detail, "Off", sizeof ua->reg.detail);
            changed(ua);
            return;
        }
        int g = granted_expires(ua, m);
        if (g <= 0)
            g = ua->cfg.expires;
        ua->reg.granted = g;
        ua->reg.auth_tries = 0;
        ua->reg.backoff = 0;
        char now_ct[320];
        contact_hv(ua, now_ct, sizeof now_ct);
        if (strcmp(now_ct, ua->reg.contact) != 0 && !ua->reg.recontact_done) {
            sp_log("public address is %s, registering again with it", ua->pub_text);
            ua->reg.recontact_done = 1;
            reg_send(ua, ua->cfg.expires, NULL);
            return;
        }
        int r = g > 60 ? g * 85 / 100 : g / 2;
        if (r < 15)
            r = 15;
        ua->reg.refresh_at = sp_now_ms() + (int64_t)r * 1000;
        int was = ua->reg.state;
        ua->reg.state = SP_REG_OK;
        sp_strlcpy(ua->reg.detail, "Registered", sizeof ua->reg.detail);
        sp_log("registered for %ds, refresh in %ds", g, r);
        if (was != SP_REG_OK)
            changed(ua);
        return;
    }
    if ((st == 401 || st == 407) && ua->reg.auth_tries < 2) {
        const char *chv = sp_hdr_get(m, st == 401 ? "WWW-Authenticate" : "Proxy-Authenticate");
        sp_challenge ch;
        int pr = chv ? sp_challenge_parse(chv, &ch) : -1;
        if (pr == 0) {
            if (!ch.stale)
                ua->reg.auth_tries++;
            if (strcmp(ch.nonce, ua->nc_nonce) != 0) {
                ua->nc = 0;
                sp_strlcpy(ua->nc_nonce, ch.nonce, sizeof ua->nc_nonce);
            }
            char ruri[160], dig[1400], line[1500];
            snprintf(ruri, sizeof ruri, "sip:%s", ua->cfg.server);
            const char *au = ua->cfg.auth_user[0] ? ua->cfg.auth_user : ua->cfg.user;
            if (sp_digest_build(dig, sizeof dig, &ch, "REGISTER", ruri, au, ua->cfg.password,
                                &ua->nc) == 0) {
                snprintf(line, sizeof line, "%s: %s",
                         st == 401 ? "Authorization" : "Proxy-Authorization", dig);
                reg_send(ua, ua->reg.unregistering ? 0 : ua->cfg.expires, line);
                return;
            }
        }
        reg_fail(ua, st, pr == -2 ? "Server wants an unsupported auth algorithm" : NULL);
        return;
    }
    if (st == 423) {
        const char *me = sp_hdr_get(m, "Min-Expires");
        int v = me ? atoi(me) : 0;
        if (v > ua->cfg.expires && v < 7200) {
            ua->cfg.expires = v;
            reg_send(ua, v, NULL);
            return;
        }
    }
    if (ua->reg.unregistering) {
        ua->reg.state = SP_REG_OFF;
        changed(ua);
        return;
    }
    reg_fail(ua, st, NULL);
}

static void learn_public(sp_ua *ua, const sp_msg *m)
{
    const char *v = sp_hdr_get(m, "Via");
    if (!v)
        return;
    char first[1][320];
    if (sp_split_commas(v, first, 1) < 1)
        return;
    char rcv[64], rp[16];
    int has_r = sp_param(first[0], "received", rcv, sizeof rcv) && rcv[0];
    int has_rp = sp_param(first[0], "rport", rp, sizeof rp) && rp[0];
    if (!has_r && !has_rp)
        return;
    const char *ip = has_r ? rcv : ua->local_ip;
    int port = has_rp ? atoi(rp) : ua->local_port;
    if (strcmp(ip, ua->pub_ip) != 0 || port != ua->pub_port) {
        sp_strlcpy(ua->pub_ip, ip, sizeof ua->pub_ip);
        ua->pub_port = port;
        snprintf(ua->pub_text, sizeof ua->pub_text, "%s:%d", ip, port);
        sp_log("public address %s (local %s:%d)", ua->pub_text, ua->local_ip, ua->local_port);
    }
}

/* ---------------------------------------------------------------- requests */

static void on_new_invite(sp_ua *ua, sp_msg *m)
{
    char tag[32];
    new_tag(tag);
    if (sp_ua_busy(ua)) {
        sp_log("second call while busy: 486");
        send_resp(ua, m, 486, "Busy Here", tag, 0, NULL, NULL, NULL);
        return;
    }
    sp_call *c = &ua->c;
    call_reset(ua);
    call_secure_setup(ua);
    int sr = take_sdp(ua, m);
    if (sr == -2) {
        send_resp(ua, m, 488, "Not Acceptable Here", tag, 0, NULL, NULL, NULL);
        call_reset(ua);
        return;
    }
    c->late_offer = sr == -1;
    c->id = ++ua->next_id;
    c->incoming = 1;
    c->state = SP_CALL_INCOMING;
    sp_strlcpy(c->ltag, tag, sizeof c->ltag);
    sp_strlcpy(c->call_id, sp_hdr_get(m, "Call-ID"), sizeof c->call_id);
    const char *from = sp_hdr_get(m, "From"), *to = sp_hdr_get(m, "To");
    strip_tag(from, c->remote_hv, sizeof c->remote_hv, c->rtag, sizeof c->rtag);
    strip_tag(to, c->local_hv, sizeof c->local_hv, NULL, 0);
    char furi[320];
    sp_hv_uri(from, furi, sizeof furi);
    sp_uri_user(furi, c->number, sizeof c->number);
    sp_hv_display(from, c->display, sizeof c->display);
    /* a trusted number from P-Asserted-Identity / Remote-Party-ID beats an anonymous From */
    const char *pai = sp_hdr_get(m, "P-Asserted-Identity");
    if (!pai)
        pai = sp_hdr_get(m, "Remote-Party-ID");
    if (pai && (!c->number[0] || sp_strcaseeq(c->number, "anonymous"))) {
        char pu[320];
        sp_hv_uri(pai, pu, sizeof pu);
        sp_uri_user(pu, c->number, sizeof c->number);
    }
    const char *ct = sp_hdr_get(m, "Contact");
    if (ct)
        sp_hv_uri(ct, c->remote_target, sizeof c->remote_target);
    else
        sp_strlcpy(c->remote_target, furi, sizeof c->remote_target);
    c->nroutes = routes_from(m, c->routes, 0);
    sp_cseq(m, &c->rcseq, NULL, 0);
    c->lcseq = 1 + sp_rand32() % 5000;
    c->sess_id = sp_rand32() & 0x7fffffff;
    c->sdp_ver = 1;

    send_resp(ua, m, 100, "Trying", NULL, 0, NULL, NULL, NULL);
    send_resp(ua, m, 180, "Ringing", c->ltag, 1, NULL, NULL, NULL);

    c->inv = *m;            /* keep the INVITE: we answer it later */
    memset(m, 0, sizeof *m);
    c->has_inv = 1;
    c->ring_deadline = sp_now_ms() + 120000;
    sp_log("incoming call %d from %s \"%s\"", c->id, c->number, c->display);
    changed(ua);
}

static void on_reinvite(sp_ua *ua, sp_msg *m)
{
    sp_call *c = &ua->c;
    for (int i = 0; i < MAX_TX; i++)
        if (ua->tx[i].used && ua->tx[i].kind == TXK_REINVITE && !ua->tx[i].completed &&
            strcmp(ua->tx[i].call_id, c->call_id) == 0) {
            send_resp(ua, m, 491, "Request Pending", NULL, 0, NULL, NULL, NULL);
            return;
        }
    sp_cseq(m, &c->rcseq, NULL, 0);
    const char *ct = sp_hdr_get(m, "Contact");
    if (ct)
        sp_hv_uri(ct, c->remote_target, sizeof c->remote_target);
    sp_sdp old = c->rsdp;
    int oldpt = c->pt;
    int sr = take_sdp(ua, m);
    if (sr == -2) {
        send_resp(ua, m, 488, "Not Acceptable Here", NULL, 0, NULL, NULL, NULL);
        return;
    }
    if (sr == 0 && (strcmp(old.ip, c->rsdp.ip) != 0 || old.port != c->rsdp.port ||
                    old.dir != c->rsdp.dir || oldpt != c->pt))
        c->sdp_ver++;
    char sdp[1024];
    local_sdp(ua, sdp, sizeof sdp, sr == 0);
    if (sr == -1)
        c->late_offer = 1;
    send_final(ua, m, 200, "OK", ALLOW_HDR, sdp);
    if (sr == 0) {
        media_apply(ua);
        changed(ua);
    }
}

static void on_ack(sp_ua *ua, const sp_msg *m)
{
    sp_call *c = &ua->c;
    const char *cid = sp_hdr_get(m, "Call-ID");
    if (!cid || strcmp(cid, c->call_id) != 0)
        return;
    uint32_t cs = 0;
    sp_cseq(m, &cs, NULL, 0);
    if (c->fin_msg && cs == c->fin_cseq) {
        free(c->fin_msg);
        c->fin_msg = NULL;
    }
    if (c->late_offer && c->state == SP_CALL_ACTIVE) {
        if (take_sdp(ua, m) == 0) {
            c->late_offer = 0;
            media_apply(ua);
        }
    }
}

static void on_cancel(sp_ua *ua, const sp_msg *m)
{
    sp_call *c = &ua->c;
    const char *cid = sp_hdr_get(m, "Call-ID");
    int match = cid && c->has_inv && strcmp(cid, c->call_id) == 0;
    if (match) {
        char b1[64], b2[64];
        sp_top_branch(m, b1, sizeof b1);
        sp_top_branch(&c->inv, b2, sizeof b2);
        match = strcmp(b1, b2) == 0;
    }
    send_resp(ua, m, match ? 200 : 481, match ? "OK" : "Call/Transaction Does Not Exist",
              c->ltag, 0, NULL, NULL, NULL);
    if (match && c->state == SP_CALL_INCOMING) {
        send_final(ua, &c->inv, 487, "Request Terminated", NULL, NULL);
        call_end(ua, "Missed call", 0);
    }
}

static void on_request(sp_ua *ua, sp_msg *m)
{
    sp_call *c = &ua->c;
    const char *meth = m->method;
    if (!sp_strcaseeq(meth, "ACK") && rc_resend(ua, m))
        return;
    const char *cid = sp_hdr_get(m, "Call-ID");
    char totag[128] = "";
    sp_param(sp_hdr_get(m, "To"), "tag", totag, sizeof totag);
    int cur = cid && c->state != SP_CALL_IDLE && strcmp(cid, c->call_id) == 0;
    int live = cur && c->state != SP_CALL_ENDED;

    if (sp_strcaseeq(meth, "ACK")) {
        on_ack(ua, m);
    } else if (sp_strcaseeq(meth, "CANCEL")) {
        on_cancel(ua, m);
    } else if (sp_strcaseeq(meth, "INVITE")) {
        if (!totag[0])
            on_new_invite(ua, m);
        else if (live && c->state == SP_CALL_ACTIVE)
            on_reinvite(ua, m);
        else
            send_resp(ua, m, 481, "Call/Transaction Does Not Exist", NULL, 0, NULL, NULL, NULL);
    } else if (sp_strcaseeq(meth, "BYE")) {
        if (live) {
            send_resp(ua, m, 200, "OK", NULL, 0, NULL, NULL, NULL);
            free(c->fin_msg);
            c->fin_msg = NULL;
            call_end(ua, c->incoming && !c->answered ? "Missed call" : "Call ended", 0);
        } else {
            send_resp(ua, m, cur ? 200 : 481, cur ? "OK" : "Call/Transaction Does Not Exist",
                      NULL, 0, NULL, NULL, NULL);
        }
    } else if (sp_strcaseeq(meth, "OPTIONS")) {
        send_resp(ua, m, 200, "OK", NULL, 0,
                  ALLOW_HDR "Accept: application/sdp\r\n", NULL, NULL);
    } else if (sp_strcaseeq(meth, "UPDATE") && live && m->blen) {
        if (take_sdp(ua, m) == 0) {
            char sdp[1024];
            c->sdp_ver++;
            local_sdp(ua, sdp, sizeof sdp, 1);
            send_resp(ua, m, 200, "OK", NULL, 1, NULL, "application/sdp", sdp);
            media_apply(ua);
        } else {
            send_resp(ua, m, 488, "Not Acceptable Here", NULL, 0, NULL, NULL, NULL);
        }
    } else if (sp_strcaseeq(meth, "NOTIFY") || sp_strcaseeq(meth, "INFO") ||
               sp_strcaseeq(meth, "UPDATE") || sp_strcaseeq(meth, "MESSAGE")) {
        send_resp(ua, m, 200, "OK", NULL, 0, NULL, NULL, NULL);
    } else {
        send_resp(ua, m, 501, "Not Implemented", NULL, 0, ALLOW_HDR, NULL, NULL);
    }
}

/* -------------------------------------------------------------- public API */

sp_ua *sp_ua_new(const sp_hooks *h)
{
    sp_ua *ua = calloc(1, sizeof *ua);
    ua->h = *h;
    ua->c.pt = ua->c.dtmf_pt = -1;
    char r[21];
    sp_rand_hex(r, 20);
    snprintf(ua->reg.call_id, sizeof ua->reg.call_id, "%s@sipphone", r);
    new_tag(ua->reg.tag);
    ua->reg.cseq = sp_rand32() % 10000;
    ua->next_id = (int)(sp_rand32() & 0x0fffffff);   /* unique across daemon restarts */
    return ua;
}

void sp_ua_free(sp_ua *ua)
{
    if (!ua)
        return;
    call_reset(ua);
    for (int i = 0; i < MAX_TX; i++)
        tx_free(&ua->tx[i]);
    for (int i = 0; i < MAX_RC; i++)
        free(ua->rc[i].resp);
    free(ua);
}

void sp_ua_configure(sp_ua *ua, const sp_cfg *cfg)
{
    ua->cfg = *cfg;
    if (ua->cfg.expires <= 0)
        ua->cfg.expires = 300;
    ua->configured = cfg->server[0] && cfg->user[0];
}

void sp_ua_set_local(sp_ua *ua, const char *ip, int port)
{
    if (strcmp(ua->local_ip, ip ? ip : "") != 0 || ua->local_port != port) {
        sp_strlcpy(ua->local_ip, ip, sizeof ua->local_ip);
        ua->local_port = port;
        ua->pub_ip[0] = 0;
        ua->pub_port = 0;
        ua->pub_text[0] = 0;
        ua->reg.recontact_done = 0;
    }
}

void sp_ua_set_rtp_port(sp_ua *ua, int port)
{
    ua->rtp_port = port;
}

void sp_ua_start(sp_ua *ua)
{
    if (!ua->configured || !ua->cfg.do_register) {
        if (ua->reg.state != SP_REG_OFF) {
            ua->reg.state = SP_REG_OFF;
            changed(ua);
        }
        sp_strlcpy(ua->reg.detail, ua->configured ? "Off" : "Not set up", sizeof ua->reg.detail);
        return;
    }
    ua->reg.auth_tries = 0;
    ua->reg.backoff = 0;
    if (ua->reg.state != SP_REG_OK && ua->reg.state != SP_REG_TRYING) {
        ua->reg.state = SP_REG_TRYING;
        sp_strlcpy(ua->reg.detail, "Registering", sizeof ua->reg.detail);
        changed(ua);
    }
    reg_send(ua, ua->cfg.expires, NULL);
}

void sp_ua_set_unreachable(sp_ua *ua, const char *why)
{
    for (int i = 0; i < MAX_TX; i++)
        if (ua->tx[i].used && ua->tx[i].kind == TXK_REGISTER)
            tx_free(&ua->tx[i]);
    ua->reg.refresh_at = ua->reg.retry_at = 0;
    ua->reg.unregistering = 0;
    int same = ua->reg.state == SP_REG_FAILED && strcmp(ua->reg.detail, why) == 0;
    ua->reg.state = SP_REG_FAILED;
    sp_strlcpy(ua->reg.detail, why, sizeof ua->reg.detail);
    if (!same)
        changed(ua);
}

void sp_ua_unregister(sp_ua *ua)
{
    ua->reg.backoff = 0;
    if (ua->reg.state == SP_REG_OK || ua->reg.state == SP_REG_TRYING) {
        reg_send(ua, 0, NULL);            /* also drops an in-flight REGISTER */
    } else {
        for (int i = 0; i < MAX_TX; i++)
            if (ua->tx[i].used && ua->tx[i].kind == TXK_REGISTER)
                tx_free(&ua->tx[i]);
        ua->reg.unregistering = 0;
    }
    ua->reg.state = SP_REG_OFF;
    ua->reg.refresh_at = ua->reg.retry_at = 0;
    sp_strlcpy(ua->reg.detail, "Off", sizeof ua->reg.detail);
    changed(ua);
}

void sp_ua_transport_reset(sp_ua *ua)
{
    for (int i = 0; i < MAX_TX; i++)
        if (ua->tx[i].used && ua->tx[i].kind != TXK_INVITE)
            tx_free(&ua->tx[i]);
    if (ua->reg.state == SP_REG_OK) {
        ua->reg.state = SP_REG_TRYING;
        sp_strlcpy(ua->reg.detail, "Reconnecting", sizeof ua->reg.detail);
        changed(ua);
    }
    ua->reg.refresh_at = 0;
}

void sp_ua_refresh_now(sp_ua *ua)
{
    if (ua->configured && ua->cfg.do_register)
        reg_send(ua, ua->cfg.expires, NULL);
}

void sp_ua_input(sp_ua *ua, const char *data, size_t len)
{
    sp_msg m;
    if (sp_msg_parse(&m, data, len) != 0) {
        sp_log("unparseable message (%u bytes) ignored", (unsigned)len);
        return;
    }
    sp_log_block("<<<", data, len);
    if (m.is_req) {
        on_request(ua, &m);
    } else {
        char br[64], meth[16];
        sp_top_branch(&m, br, sizeof br);
        sp_cseq(&m, NULL, meth, sizeof meth);
        learn_public(ua, &m);
        sp_tx *t = tx_find(ua, br, meth);
        if (t && t->completed) {
            if (m.status >= 300 && t->ack) {
                sp_log("final %d retransmitted: repeating ACK", m.status);
                raw_send(ua, t->ack, strlen(t->ack));
            }
        } else if (!t) {
            sp_call *c = &ua->c;
            const char *cid = sp_hdr_get(&m, "Call-ID");
            if (m.status >= 200 && m.status < 300 && sp_strcaseeq(meth, "INVITE") && cid &&
                strcmp(cid, c->call_id) == 0 && c->ack_msg) {
                sp_log("2xx retransmission: repeating ACK");
                raw_send(ua, c->ack_msg, strlen(c->ack_msg));
            }
        } else if (t->kind == TXK_REGISTER) {
            on_register_resp(ua, t, &m);
        } else if (t->kind == TXK_INVITE) {
            on_invite_resp(ua, t, &m);
        } else if (t->kind == TXK_REINVITE) {
            on_reinvite_resp(ua, t, &m);
        } else if (m.status >= 200) {
            tx_free(t);
        } else {
            t->prov = 1;
        }
    }
    sp_msg_free(&m);
}

void sp_ua_tick(sp_ua *ua)
{
    int64_t now = sp_now_ms();
    for (int i = 0; i < MAX_TX; i++) {
        sp_tx *t = &ua->tx[i];
        if (!t->used)
            continue;
        if (t->completed) {
            if (now >= t->deadline)
                tx_free(t);
            continue;
        }
        if (now >= t->deadline) {
            sp_log("%s timed out", t->method);
            int kind = t->kind;
            char cid[96];
            sp_strlcpy(cid, t->call_id, sizeof cid);
            tx_free(t);
            if (kind == TXK_REGISTER) {
                if (ua->reg.unregistering) {
                    ua->reg.state = SP_REG_OFF;
                    changed(ua);
                } else {
                    reg_fail(ua, 408, NULL);
                }
            } else if (kind == TXK_INVITE && strcmp(cid, ua->c.call_id) == 0 &&
                       (ua->c.state == SP_CALL_CALLING || ua->c.state == SP_CALL_RINGING)) {
                call_end(ua, ua->c.state == SP_CALL_RINGING ? "No answer" : "No response from server",
                         408);
            }
            continue;
        }
        if (t->next_rt && now >= t->next_rt) {
            raw_send(ua, t->msg, t->len);
            if (t->kind == TXK_INVITE || t->kind == TXK_REINVITE)
                t->interval *= 2;
            else
                t->interval = t->prov ? T2 : (t->interval * 2 > T2 ? T2 : t->interval * 2);
            t->next_rt = now + t->interval;
        }
    }
    sp_call *c = &ua->c;
    if (c->state == SP_CALL_INCOMING && c->ring_deadline && now >= c->ring_deadline) {
        sp_log("incoming call %d rang for 120 s with no answer or CANCEL", c->id);
        c->ring_deadline = 0;
        if (c->has_inv)
            send_final(ua, &c->inv, 480, "Temporarily Unavailable", NULL, NULL);
        call_end(ua, "Missed call", 0);
    }
    if (c->fin_msg) {
        if (now >= c->fin_deadline) {
            int was2xx = c->fin_2xx;
            free(c->fin_msg);
            c->fin_msg = NULL;
            if (was2xx && c->state == SP_CALL_ACTIVE) {
                sp_log("no ACK for our 200 OK: hanging up");
                send_bye(ua);
                call_end(ua, "Call failed (no ACK)", 408);
            }
        } else if (c->fin_next && now >= c->fin_next) {
            raw_send(ua, c->fin_msg, strlen(c->fin_msg));
            c->fin_interval = c->fin_interval * 2 > T2 ? T2 : c->fin_interval * 2;
            c->fin_next = now + c->fin_interval;
        }
    }
    int want = ua->configured && ua->cfg.do_register;
    if (ua->reg.refresh_at && now >= ua->reg.refresh_at) {
        ua->reg.refresh_at = 0;           /* always clear a due deadline, or poll spins at 0 ms */
        if (want)
            reg_send(ua, ua->cfg.expires, NULL);
    }
    if (ua->reg.retry_at && now >= ua->reg.retry_at) {
        ua->reg.retry_at = 0;
        if (want)
            reg_send(ua, ua->cfg.expires, NULL);
    }
}

int64_t sp_ua_next_timer(sp_ua *ua)
{
    int64_t n = -1;
#define CONSIDER(v) do { int64_t _v = (v); if (_v > 0 && (n < 0 || _v < n)) n = _v; } while (0)
    for (int i = 0; i < MAX_TX; i++) {
        if (!ua->tx[i].used)
            continue;
        CONSIDER(ua->tx[i].deadline);
        CONSIDER(ua->tx[i].next_rt);
    }
    if (ua->c.fin_msg) {
        CONSIDER(ua->c.fin_deadline);
        CONSIDER(ua->c.fin_next);
    }
    CONSIDER(ua->reg.refresh_at);
    CONSIDER(ua->reg.retry_at);
#undef CONSIDER
    return n;
}

int64_t sp_ua_next_refresh(sp_ua *ua)
{
    if (ua->reg.refresh_at)
        return ua->reg.refresh_at;
    if (ua->reg.retry_at)
        return ua->reg.retry_at;
    return -1;
}

int sp_ua_dial(sp_ua *ua, const char *number)
{
    if (!ua->configured || !number || !number[0])
        return -1;
    if (sp_ua_busy(ua))
        return -1;
    call_reset(ua);
    call_secure_setup(ua);
    sp_call *c = &ua->c;
    c->id = ++ua->next_id;
    c->incoming = 0;
    c->state = SP_CALL_CALLING;
    sp_strlcpy(c->number, number, sizeof c->number);
    char r[21];
    sp_rand_hex(r, 20);
    snprintf(c->call_id, sizeof c->call_id, "%s@sipphone", r);
    new_tag(c->ltag);
    char uri[200];
    aor(ua, uri, sizeof uri);
    name_addr(ua, uri, c->local_hv, sizeof c->local_hv);
    snprintf(c->remote_target, sizeof c->remote_target, "sip:%s@%s", number, ua->cfg.server);
    snprintf(c->remote_hv, sizeof c->remote_hv, "<%s>", c->remote_target);
    c->lcseq = 1 + sp_rand32() % 5000;
    c->sess_id = sp_rand32() & 0x7fffffff;
    c->sdp_ver = 1;
    sp_log("dialing call %d to %s", c->id, number);
    send_invite(ua, NULL);
    changed(ua);
    return c->id;
}

int sp_ua_answer(sp_ua *ua)
{
    sp_call *c = &ua->c;
    if (c->state != SP_CALL_INCOMING || !c->has_inv)
        return -1;
    char sdp[1024];
    local_sdp(ua, sdp, sizeof sdp, !c->late_offer);
    send_final(ua, &c->inv, 200, "OK", ALLOW_HDR, sdp);
    c->state = SP_CALL_ACTIVE;
    c->answered = 1;
    c->connected_at = (long)time(NULL);
    if (!c->late_offer)
        media_apply(ua);
    sp_log("answered call %d", c->id);
    changed(ua);
    return 0;
}

void sp_ua_hangup(sp_ua *ua)
{
    sp_call *c = &ua->c;
    switch (c->state) {
    case SP_CALL_CALLING:
    case SP_CALL_RINGING: {
        sp_tx *t = tx_find_invite(ua, c->call_id);
        if (t) {
            if (t->prov)
                send_cancel(ua, t);
            else
                t->cancel_pending = 1;
        }
        call_end(ua, "Call ended", 0);
        break;
    }
    case SP_CALL_INCOMING:
        if (c->has_inv)
            send_final(ua, &c->inv, 486, "Busy Here", NULL, NULL);
        call_end(ua, "Declined", 0);
        break;
    case SP_CALL_ACTIVE:
        free(c->fin_msg);
        c->fin_msg = NULL;
        send_bye(ua);
        call_end(ua, "Call ended", 0);
        break;
    default:
        break;
    }
}

void sp_ua_hold(sp_ua *ua, int on)
{
    sp_call *c = &ua->c;
    on = !!on;
    if (c->state != SP_CALL_ACTIVE || c->local_hold == on)
        return;
    c->local_hold = on;
    c->lcseq++;
    c->sdp_ver++;
    char sdp[1024], br[48];
    local_sdp(ua, sdp, sizeof sdp, 0);
    new_branch(br);
    char *m = build_indialog(ua, "INVITE", c->lcseq, br, 1, ALLOW_HDR, "application/sdp", sdp);
    tx_start(ua, TXK_REINVITE, "INVITE", c->lcseq, br, c->call_id, m);
    media_apply(ua);
    changed(ua);
}

void sp_ua_clear_ended(sp_ua *ua)
{
    if (ua->c.state == SP_CALL_ENDED) {
        ua->c.state = SP_CALL_IDLE;
        changed(ua);
    }
}

int sp_ua_reg_state(const sp_ua *ua)
{
    return ua->reg.state;
}

const char *sp_ua_reg_detail(const sp_ua *ua)
{
    return ua->reg.detail;
}

int sp_ua_reg_expires(const sp_ua *ua)
{
    return ua->reg.granted;
}

void sp_ua_call(const sp_ua *ua, sp_call_info *o)
{
    const sp_call *c = &ua->c;
    memset(o, 0, sizeof *o);
    o->id = c->id;
    o->state = c->state;
    o->incoming = c->incoming;
    sp_strlcpy(o->number, c->number, sizeof o->number);
    sp_strlcpy(o->display, c->display, sizeof o->display);
    sp_strlcpy(o->reason, c->reason, sizeof o->reason);
    o->status = c->status;
    o->connected_at = c->connected_at;
    o->answered = c->answered;
    o->held = c->local_hold;
    o->remote_held = c->have_rsdp && (c->rsdp.dir == SP_DIR_SENDONLY || c->rsdp.dir == SP_DIR_INACTIVE);
}

int sp_ua_busy(const sp_ua *ua)
{
    int s = ua->c.state;
    return s == SP_CALL_CALLING || s == SP_CALL_RINGING || s == SP_CALL_INCOMING ||
           s == SP_CALL_ACTIVE;
}

const char *sp_ua_public_addr(const sp_ua *ua)
{
    return ua->pub_text;
}

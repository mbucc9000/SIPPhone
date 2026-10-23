/* Host test harness for the SIP engine. Builds on Windows (MSVC) or POSIX.
   It wires sp_ua's hooks to an in-memory "network" and a scripted peer, so the
   whole registration + call state machine runs with no sockets. */
#include "sp_ua.h"
#include "sp_sip.h"
#include "sp_sdp.h"
#include "sp_md5.h"
#include "sp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;
#define CHECK(c, ...) do { if (c) { g_pass++; } else { \
    g_fail++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- captured side effects ---- */

typedef struct {
    char last_tx[8192];
    int  tx_count;
    char tx_methods[64][24];   /* request method or "<status>" */
    int  tx_n;
    int  media_on, media_pt, media_dtmf, media_dir, media_port;
    char media_ip[64];
    int  media_secure;
    int  tone;
    int  changes;
} caps;

static caps g_cap;
static sp_ua *g_ua;
static char g_last_req[8192];   /* last REQUEST the UA sent; survives reset_caps */

static void reset_caps(void)
{
    memset(&g_cap, 0, sizeof g_cap);
}

static void start_line_tag(const char *data, char *out, size_t n)
{
    if (strncmp(data, "SIP/2.0 ", 8) == 0) {
        int st = atoi(data + 8);
        snprintf(out, n, "%d", st);
    } else {
        size_t l = strcspn(data, " ");
        if (l >= n)
            l = n - 1;
        memcpy(out, data, l);
        out[l] = 0;
    }
}

static void h_send(void *ctx, const char *data, size_t len)
{
    (void)ctx;
    g_cap.tx_count++;
    size_t n = len < sizeof g_cap.last_tx - 1 ? len : sizeof g_cap.last_tx - 1;
    memcpy(g_cap.last_tx, data, n);
    g_cap.last_tx[n] = 0;
    if (strncmp(data, "SIP/2.0 ", 8) != 0) {
        memcpy(g_last_req, data, n);
        g_last_req[n] = 0;
    }
    if (g_cap.tx_n < 64)
        start_line_tag(data, g_cap.tx_methods[g_cap.tx_n++], 24);
}

static void h_changed(void *ctx) { (void)ctx; g_cap.changes++; }

static void h_media(void *ctx, const sp_media_info *m)
{
    (void)ctx;
    g_cap.media_on = m->on;
    g_cap.media_pt = m->pt;
    g_cap.media_dtmf = m->dtmf_pt;
    g_cap.media_dir = m->dir;
    g_cap.media_port = m->port;
    g_cap.media_secure = m->secure;
    sp_strlcpy(g_cap.media_ip, m->ip ? m->ip : "", sizeof g_cap.media_ip);
}

static void h_tone(void *ctx, int tone) { (void)ctx; g_cap.tone = tone; }

/* ---- helpers to read the last thing the UA transmitted ---- */

static int last_is(const char *tag)
{
    char t[24];
    start_line_tag(g_cap.last_tx, t, sizeof t);
    return strcmp(t, tag) == 0;
}

static const char *last_hdr(const char *name)
{
    static sp_msg m;
    static int have;
    if (have)
        sp_msg_free(&m);
    have = sp_msg_parse(&m, g_cap.last_tx, strlen(g_cap.last_tx)) == 0;
    return have ? sp_hdr_get(&m, name) : NULL;
}

static int sent_method(const char *tag)
{
    for (int i = 0; i < g_cap.tx_n; i++)
        if (strcmp(g_cap.tx_methods[i], tag) == 0)
            return 1;
    return 0;
}

/* Builds a response to the UA's last request, echoing the dialog headers. */
static char *build_response(int status, const char *reason, const char *extra_to_tag,
                           const char *extra_hdrs, const char *body)
{
    sp_msg req;
    if (sp_msg_parse(&req, g_last_req, strlen(g_last_req)) != 0 || !req.is_req) {
        printf("  (build_response: no request to respond to)\n");
        if (req.raw)
            sp_msg_free(&req);
        return NULL;
    }
    sp_buf b;
    sp_buf_init(&b);
    sp_buf_printf(&b, "SIP/2.0 %d %s\r\n", status, reason);
    const char *vias[8];
    int nv = sp_hdr_all(&req, "Via", vias, 8);
    for (int i = 0; i < nv; i++)
        sp_buf_printf(&b, "Via: %s\r\n", vias[i]);
    sp_buf_printf(&b, "From: %s\r\n", sp_hdr_get(&req, "From"));
    const char *to = sp_hdr_get(&req, "To");
    if (extra_to_tag && !sp_param(to, "tag", NULL, 0))
        sp_buf_printf(&b, "To: %s;tag=%s\r\n", to, extra_to_tag);
    else
        sp_buf_printf(&b, "To: %s\r\n", to);
    sp_buf_printf(&b, "Call-ID: %s\r\nCSeq: %s\r\n", sp_hdr_get(&req, "Call-ID"),
                  sp_hdr_get(&req, "CSeq"));
    if (extra_hdrs)
        sp_buf_puts(&b, extra_hdrs);
    if (body && *body)
        sp_buf_printf(&b, "Content-Type: application/sdp\r\nContent-Length: %u\r\n\r\n%s",
                      (unsigned)strlen(body), body);
    else
        sp_buf_puts(&b, "Content-Length: 0\r\n\r\n");
    sp_msg_free(&req);
    return sp_buf_take(&b);
}

static void feed_response(sp_ua *ua, int status, const char *reason, const char *extra_to_tag,
                          const char *extra_hdrs, const char *body)
{
    char *r = build_response(status, reason, extra_to_tag, extra_hdrs, body);
    if (r) {
        sp_ua_input(ua, r, strlen(r));
        free(r);
    }
}

static const char *SDP_OFFER =
    "v=0\r\no=peer 1 1 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\n"
    "t=0 0\r\nm=audio 40000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n";

static const char *SDP_ANSWER =
    "v=0\r\no=peer 2 2 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\n"
    "t=0 0\r\nm=audio 40000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n";

static sp_ua *make_ua(int do_register)
{
    sp_hooks h = { 0 };
    h.send = h_send;
    h.changed = h_changed;
    h.media = h_media;
    h.tone = h_tone;
    sp_ua *ua = sp_ua_new(&h);
    sp_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    sp_strlcpy(cfg.server, "chicago4.voip.ms", sizeof cfg.server);
    sp_strlcpy(cfg.user, "100000_sub", sizeof cfg.user);
    sp_strlcpy(cfg.password, "s3cret", sizeof cfg.password);
    sp_strlcpy(cfg.display, "Alex", sizeof cfg.display);
    cfg.do_register = do_register;
    cfg.expires = 120;
    sp_ua_configure(ua, &cfg);
    sp_ua_set_local(ua, "192.0.2.10", 5060);
    sp_ua_set_rtp_port(ua, 7078);
    return ua;
}

/* ---- the 401 challenge VoIP.ms sends first ---- */
static const char *WWW_AUTH =
    "WWW-Authenticate: Digest realm=\"chicago4.voip.ms\", "
    "nonce=\"abc123nonce\", qop=\"auth\", algorithm=MD5\r\n";

/* verify a digest Authorization the UA produced actually matches the password */
static int check_digest(const char *authhdr, const char *method, const char *pass)
{
    if (!authhdr)
        return 0;
    sp_challenge ch;
    char realm[128] = "", nonce[256] = "", uri[256] = "", resp[64] = "", user[64] = "";
    char cnonce[64] = "", nc[16] = "", qop[16] = "";
    /* crude param pull */
    const char *p;
    #define GET(k, dst) do { p = strstr(authhdr, k "=\""); if (p) { p += strlen(k) + 2; \
        size_t l = strcspn(p, "\""); if (l < sizeof dst) { memcpy(dst, p, l); dst[l] = 0; } } } while (0)
    GET("realm", realm); GET("nonce", nonce); GET("uri", uri); GET("response", resp);
    GET("username", user); GET("cnonce", cnonce);
    p = strstr(authhdr, "nc="); if (p) { p += 3; size_t l = strcspn(p, ", "); if (l < sizeof nc) { memcpy(nc, p, l); nc[l] = 0; } }
    p = strstr(authhdr, "qop="); if (p) { p += 4; size_t l = strcspn(p, ", "); if (l < sizeof qop) { memcpy(qop, p, l); qop[l] = 0; } }
    #undef GET
    char ha1in[400], ha2in[400], ri[600], ha1[33], ha2[33], want[33];
    snprintf(ha1in, sizeof ha1in, "%s:%s:%s", user, realm, pass);
    sp_md5_hex(ha1in, ha1);
    snprintf(ha2in, sizeof ha2in, "%s:%s", method, uri);
    sp_md5_hex(ha2in, ha2);
    if (qop[0])
        snprintf(ri, sizeof ri, "%s:%s:%s:%s:auth:%s", ha1, nonce, nc, cnonce, ha2);
    else
        snprintf(ri, sizeof ri, "%s:%s:%s", ha1, nonce, ha2);
    sp_md5_hex(ri, want);
    (void)ch;
    return strcmp(want, resp) == 0;
}

/* ================================================================ tests */

static void t_register(void)
{
    printf("[register + auth + rport]\n");
    reset_caps();
    sp_ua *ua = make_ua(1);
    g_ua = ua;
    sp_ua_start(ua);
    CHECK(last_is("REGISTER"), "first tx should be REGISTER");
    CHECK(sp_ua_reg_state(ua) == SP_REG_TRYING, "state TRYING, got %d", sp_ua_reg_state(ua));
    const char *ex = last_hdr("Expires");
    CHECK(ex && atoi(ex) == 120, "Expires 120");

    feed_response(ua, 401, "Unauthorized", "svrtag", WWW_AUTH, NULL);
    CHECK(last_is("REGISTER"), "re-REGISTER after 401");
    const char *auth = last_hdr("Authorization");
    CHECK(auth != NULL, "Authorization header present");
    CHECK(check_digest(auth, "REGISTER", "s3cret"), "digest response matches password");
    CHECK(check_digest(auth, "REGISTER", "wrong") == 0, "digest rejects wrong password");

    /* grant, but report a different public address via rport/received */
    feed_response(ua, 200, "OK",
                  NULL,
                  "Contact: <sip:100000_sub@192.0.2.10:5060>;expires=120\r\n", NULL);
    /* UA learned nothing yet because our response Via had no received/rport;
       add them on this OK path by re-sending with them. */
    (void)0;
    CHECK(sp_ua_reg_state(ua) == SP_REG_OK, "registered OK, state=%d (%s)",
          sp_ua_reg_state(ua), sp_ua_reg_detail(ua));
    CHECK(sp_ua_reg_expires(ua) == 120, "granted expires 120, got %d", sp_ua_reg_expires(ua));

    sp_ua_free(ua);
}

static void t_register_rport(void)
{
    printf("[register learns public address from rport]\n");
    reset_caps();
    sp_ua *ua = make_ua(1);
    sp_ua_start(ua);
    /* 401 with the Via rewritten the way a real server does it: the empty
       ;rport the UA sent is filled in, and ;received is added. */
    sp_msg req;
    sp_msg_parse(&req, g_cap.last_tx, strlen(g_cap.last_tx));
    char via[400];
    sp_strlcpy(via, sp_hdr_get(&req, "Via"), sizeof via);
    char from[400], to[400], cid[160], cs[64];
    sp_strlcpy(from, sp_hdr_get(&req, "From"), sizeof from);
    sp_strlcpy(to, sp_hdr_get(&req, "To"), sizeof to);
    sp_strlcpy(cid, sp_hdr_get(&req, "Call-ID"), sizeof cid);
    sp_strlcpy(cs, sp_hdr_get(&req, "CSeq"), sizeof cs);
    sp_msg_free(&req);
    char *rp = strstr(via, ";rport");       /* fill in the value in place */
    if (rp)
        *rp = 0;
    char vias2[500];
    snprintf(vias2, sizeof vias2, "%s;received=203.0.113.9;rport=34567", via);
    {
        sp_buf b; sp_buf_init(&b);
        sp_buf_printf(&b, "SIP/2.0 401 Unauthorized\r\nVia: %s\r\n", vias2);
        sp_buf_printf(&b, "From: %s\r\nTo: %s;tag=st\r\nCall-ID: %s\r\nCSeq: %s\r\n%sContent-Length: 0\r\n\r\n",
                      from, to, cid, cs, WWW_AUTH);
        sp_ua_input(ua, b.s, b.len);
        sp_buf_free(&b);
    }
    CHECK(strcmp(sp_ua_public_addr(ua), "203.0.113.9:34567") == 0,
          "learned public addr, got '%s'", sp_ua_public_addr(ua));
    /* the re-REGISTER with auth should now carry the public Contact */
    const char *ct = last_hdr("Contact");
    CHECK(ct && strstr(ct, "203.0.113.9:34567"), "Contact uses public addr: %s", ct ? ct : "(none)");
    sp_ua_free(ua);
}

static void t_outgoing(void)
{
    printf("[outgoing call: 100 -> 180 -> 200 -> ACK -> BYE]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    int id = sp_ua_dial(ua, "13105551234");
    CHECK(id > 0, "dial returned id");
    CHECK(last_is("INVITE"), "INVITE sent");
    const char *ruri;
    sp_msg req; sp_msg_parse(&req, g_cap.last_tx, strlen(g_cap.last_tx));
    ruri = req.ruri;
    CHECK(ruri && strstr(ruri, "13105551234@chicago4.voip.ms"), "R-URI to the dialed number");
    CHECK(req.blen > 0 && strstr(req.body, "m=audio"), "INVITE carries an SDP offer");
    sp_msg_free(&req);

    feed_response(ua, 100, "Trying", NULL, NULL, NULL);
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_CALLING, "still CALLING after 100");

    feed_response(ua, 180, "Ringing", "peer", NULL, NULL);
    sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_RINGING, "RINGING after 180");
    CHECK(g_cap.tone == SP_TONE_RINGBACK, "ringback tone on");

    reset_caps();
    feed_response(ua, 200, "OK", "peer", "Contact: <sip:13105551234@198.51.100.7>\r\n", SDP_ANSWER);
    CHECK(sent_method("ACK"), "ACK sent after 200");
    sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ACTIVE, "ACTIVE after 200, got %d", ci.state);
    CHECK(g_cap.media_on && g_cap.media_pt == 0, "media up with PCMU (pt %d)", g_cap.media_pt);
    CHECK(strcmp(g_cap.media_ip, "198.51.100.7") == 0 && g_cap.media_port == 40000, "media addr");
    CHECK(g_cap.tone == SP_TONE_NONE, "ringback stopped");

    reset_caps();
    sp_ua_hangup(ua);
    CHECK(sent_method("BYE"), "BYE sent on hangup");
    feed_response(ua, 200, "OK", NULL, NULL, NULL);
    sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ENDED, "ENDED after BYE");
    CHECK(g_cap.media_on == 0, "media torn down");
    sp_ua_free(ua);
}

static void t_outgoing_auth(void)
{
    printf("[outgoing call challenged with 407]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "18005550000");
    feed_response(ua, 100, "Trying", NULL, NULL, NULL);
    feed_response(ua, 407, "Proxy Authentication Required", "p",
                  "Proxy-Authenticate: Digest realm=\"chicago4.voip.ms\", nonce=\"n2\", qop=\"auth\", algorithm=MD5\r\n",
                  NULL);
    CHECK(sent_method("ACK"), "ACK the 407");
    CHECK(last_is("INVITE"), "new INVITE with auth");
    const char *pa = last_hdr("Proxy-Authorization");
    CHECK(pa && check_digest(pa, "INVITE", "s3cret"), "proxy digest matches");
    /* CSeq must have incremented on the resend */
    uint32_t cs = 0; char meth[16];
    sp_msg req; sp_msg_parse(&req, g_cap.last_tx, strlen(g_cap.last_tx));
    sp_cseq(&req, &cs, meth, sizeof meth);
    sp_msg_free(&req);
    CHECK(cs >= 2, "CSeq incremented, got %u", cs);
    sp_ua_free(ua);
}

static void t_busy(void)
{
    printf("[outgoing to a busy number -> 486]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "15550001111");
    feed_response(ua, 100, "Trying", NULL, NULL, NULL);
    feed_response(ua, 486, "Busy Here", "p", NULL, NULL);
    CHECK(sent_method("ACK"), "ACK the 486");
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ENDED && ci.status == 486, "ended busy, status %d", ci.status);
    CHECK(strcmp(ci.reason, "Busy") == 0, "reason Busy, got '%s'", ci.reason);
    sp_ua_free(ua);
}

static void t_cancel(void)
{
    printf("[hang up while ringing -> CANCEL]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "15550002222");
    feed_response(ua, 180, "Ringing", "p", NULL, NULL);
    reset_caps();
    sp_ua_hangup(ua);
    CHECK(sent_method("CANCEL"), "CANCEL sent");
    feed_response(ua, 200, "OK", NULL, NULL, NULL);   /* 200 to CANCEL */
    /* server then sends 487 to the INVITE */
    /* craft 487 against the original INVITE still tracked */
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ENDED, "ended after cancel");
    sp_ua_free(ua);
}

static void t_incoming(void)
{
    printf("[incoming call -> answer -> remote BYE]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    const char *invite =
        "INVITE sip:100000_sub@192.0.2.10:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKinc1;rport\r\n"
        "Max-Forwards: 70\r\n"
        "From: \"JOHN SMITH\" <sip:13105559999@chicago4.voip.ms>;tag=remote1\r\n"
        "To: <sip:100000_sub@chicago4.voip.ms>\r\n"
        "Call-ID: callinc1@198.51.100.7\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:13105559999@198.51.100.7:5060>\r\n"
        "Content-Type: application/sdp\r\nContent-Length: %u\r\n\r\n%s";
    char buf[2048];
    snprintf(buf, sizeof buf, invite, (unsigned)strlen(SDP_OFFER), SDP_OFFER);
    sp_ua_input(ua, buf, strlen(buf));

    CHECK(sent_method("100"), "sent 100 Trying");
    CHECK(sent_method("180"), "sent 180 Ringing");
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_INCOMING, "state INCOMING");
    CHECK(ci.incoming == 1, "flagged incoming");
    CHECK(strcmp(ci.number, "13105559999") == 0, "caller number, got '%s'", ci.number);
    CHECK(strcmp(ci.display, "JOHN SMITH") == 0, "caller name, got '%s'", ci.display);

    reset_caps();
    sp_ua_answer(ua);
    CHECK(last_is("200"), "answered with 200 OK");
    const char *ct = last_hdr("Content-Type");
    CHECK(ct && strstr(ct, "application/sdp"), "200 carries SDP answer");
    sp_msg req; sp_msg_parse(&req, g_cap.last_tx, strlen(g_cap.last_tx));
    sp_sdp ans; int ok = sp_sdp_parse(req.body, req.blen, &ans) == 0;
    sp_msg_free(&req);
    CHECK(ok && ans.npts >= 1 && ans.pts[0] == 0, "answer selects PCMU");
    CHECK(g_cap.media_on && g_cap.media_dir == SP_DIR_SENDRECV, "media sendrecv");

    /* peer ACKs */
    const char *ack =
        "ACK sip:100000_sub@192.0.2.10:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKack1\r\n"
        "From: \"JOHN SMITH\" <sip:13105559999@chicago4.voip.ms>;tag=remote1\r\n"
        "To: <sip:100000_sub@chicago4.voip.ms>;tag=%s\r\n"
        "Call-ID: callinc1@198.51.100.7\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";
    /* grab our local tag from the To of the 200 we sent (already freed); re-answer path:
       pull tag from current call by sending BYE from peer with our tag unknown -> use wildcard match on Call-ID */
    char abuf[1024];
    snprintf(abuf, sizeof abuf, ack, "ignored");
    sp_ua_input(ua, abuf, strlen(abuf));

    reset_caps();
    const char *bye =
        "BYE sip:100000_sub@192.0.2.10:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKbye1\r\n"
        "From: <sip:13105559999@chicago4.voip.ms>;tag=remote1\r\n"
        "To: <sip:100000_sub@chicago4.voip.ms>;tag=ignored\r\n"
        "Call-ID: callinc1@198.51.100.7\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
    sp_ua_input(ua, bye, strlen(bye));
    CHECK(last_is("200"), "200 to BYE");
    sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ENDED && ci.answered, "ended, was answered");
    CHECK(g_cap.media_on == 0, "media down after BYE");
    sp_ua_free(ua);
}

static void t_incoming_decline(void)
{
    printf("[incoming call declined -> 486]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    char buf[2048];
    const char *invite =
        "INVITE sip:100000_sub@192.0.2.10:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKinc2;rport\r\n"
        "From: <sip:anonymous@anonymous.invalid>;tag=r2\r\n"
        "To: <sip:100000_sub@chicago4.voip.ms>\r\n"
        "Call-ID: callinc2@198.51.100.7\r\nCSeq: 1 INVITE\r\n"
        "P-Asserted-Identity: <sip:17145550000@chicago4.voip.ms>\r\n"
        "Contact: <sip:x@198.51.100.7>\r\nContent-Type: application/sdp\r\nContent-Length: %u\r\n\r\n%s";
    snprintf(buf, sizeof buf, invite, (unsigned)strlen(SDP_OFFER), SDP_OFFER);
    sp_ua_input(ua, buf, strlen(buf));
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(strcmp(ci.number, "17145550000") == 0, "P-Asserted-Identity used for anon caller, got '%s'", ci.number);
    reset_caps();
    sp_ua_hangup(ua);
    CHECK(last_is("486"), "declined with 486");
    sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ENDED && !ci.answered, "ended, not answered (missed/declined)");
    sp_ua_free(ua);
}

static void t_glare_busy(void)
{
    printf("[second incoming while on a call -> 486]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "15550003333");
    feed_response(ua, 200, "OK", "p", "Contact: <sip:x@198.51.100.7>\r\n", SDP_ANSWER);
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ACTIVE, "first call active");
    reset_caps();
    char buf[2048];
    const char *invite =
        "INVITE sip:100000_sub@192.0.2.10:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKglare;rport\r\n"
        "From: <sip:15559998888@chicago4.voip.ms>;tag=g1\r\n"
        "To: <sip:100000_sub@chicago4.voip.ms>\r\n"
        "Call-ID: glarecall@198.51.100.7\r\nCSeq: 1 INVITE\r\n"
        "Contact: <sip:y@198.51.100.7>\r\nContent-Type: application/sdp\r\nContent-Length: %u\r\n\r\n%s";
    snprintf(buf, sizeof buf, invite, (unsigned)strlen(SDP_OFFER), SDP_OFFER);
    sp_ua_input(ua, buf, strlen(buf));
    CHECK(last_is("486"), "busy here to the 2nd call");
    sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ACTIVE, "first call still active");
    sp_ua_free(ua);
}

static void t_hold(void)
{
    printf("[hold / unhold via re-INVITE]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "15550004444");
    feed_response(ua, 200, "OK", "p", "Contact: <sip:x@198.51.100.7>\r\n", SDP_ANSWER);
    reset_caps();
    sp_ua_hold(ua, 1);
    CHECK(last_is("INVITE"), "re-INVITE for hold");
    sp_msg req; sp_msg_parse(&req, g_cap.last_tx, strlen(g_cap.last_tx));
    CHECK(strstr(req.body, "sendonly") != NULL, "offer is sendonly on hold");
    sp_msg_free(&req);
    feed_response(ua, 200, "OK", "p", "Contact: <sip:x@198.51.100.7>\r\n", SDP_ANSWER);
    CHECK(sent_method("ACK"), "ACK the hold 200");
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.held, "flagged held");
    reset_caps();
    sp_ua_hold(ua, 0);
    sp_msg_parse(&req, g_cap.last_tx, strlen(g_cap.last_tx));
    CHECK(strstr(req.body, "sendrecv") != NULL, "offer back to sendrecv");
    sp_msg_free(&req);
    sp_ua_free(ua);
}

static void t_frame(void)
{
    printf("[TCP framing]\n");
    const char *two =
        "OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/TCP a;branch=z1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP a;branch=z2\r\nCSeq: 1 OPTIONS\r\nContent-Length: 4\r\n\r\nbody";
    long n1 = sp_frame(two, strlen(two));
    CHECK(n1 > 0 && (size_t)n1 < strlen(two), "first message framed at %ld", n1);
    long n2 = sp_frame(two + n1, strlen(two) - n1);
    CHECK((size_t)(n1 + n2) == strlen(two), "second message consumes rest (%ld + %ld)", n1, n2);
    /* partial */
    long p = sp_frame(two, 20);
    CHECK(p == 0, "incomplete header returns 0, got %ld", p);
    /* leading keepalive CRLF */
    long k = sp_frame("\r\n\r\nOPTIONS", 11);
    CHECK(k < 0, "keepalive CRLFs skipped, got %ld", k);
}

static void t_sdp(void)
{
    printf("[SDP parse edge cases]\n");
    sp_sdp s;
    const char *hold = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n"
                       "m=audio 5000 RTP/AVP 8 0\r\na=sendonly\r\n";
    CHECK(sp_sdp_parse(hold, strlen(hold), &s) == 0, "hold sdp parses");
    CHECK(s.dir == SP_DIR_SENDONLY, "direction sendonly");
    CHECK(sp_sdp_choose(&s) == 8, "picks PCMA first when listed first");
    const char *zero = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
                       "m=audio 5000 RTP/AVP 0\r\n";
    CHECK(sp_sdp_parse(zero, strlen(zero), &s) == 0, "0.0.0.0 hold parses");
    CHECK(s.dir == SP_DIR_INACTIVE, "0.0.0.0 treated as inactive");
    const char *g729 = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n"
                       "m=audio 5000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n";
    CHECK(sp_sdp_parse(g729, strlen(g729), &s) == 0, "g729-only parses");
    CHECK(sp_sdp_choose(&s) == -1, "no common codec -> -1");
}


static int count_sent(const char *tag)
{
    int n = 0;
    for (int i = 0; i < g_cap.tx_n; i++)
        if (strcmp(g_cap.tx_methods[i], tag) == 0)
            n++;
    return n;
}

static void t_retrans_final(void)
{
    printf("[retransmitted 603 gets the same ACK again]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "443");
    feed_response(ua, 100, "Trying", NULL, NULL, NULL);
    char *r603 = build_response(603, "Declined", "srv", NULL, NULL);
    reset_caps();
    sp_ua_input(ua, r603, strlen(r603));
    CHECK(count_sent("ACK") == 1, "first 603 -> one ACK, got %d", count_sent("ACK"));
    char first_ack[2048];
    sp_strlcpy(first_ack, g_cap.last_tx, sizeof first_ack);
    sp_ua_input(ua, r603, strlen(r603));
    sp_ua_input(ua, r603, strlen(r603));
    CHECK(count_sent("ACK") == 3, "each retransmission re-ACKed, got %d", count_sent("ACK"));
    CHECK(count_sent("INVITE") == 0, "no new INVITE on retransmission");
    CHECK(strcmp(first_ack, g_cap.last_tx) == 0, "the repeated ACK is byte-identical");
    sp_call_info ci; sp_ua_call(ua, &ci);
    CHECK(ci.state == SP_CALL_ENDED && ci.status == 603, "call stays ended (603)");
    free(r603);
    sp_ua_free(ua);
}

static void t_retrans_401(void)
{
    printf("[retransmitted 401 does not re-send the authenticated INVITE]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "13125550100");
    char *r401 = build_response(401, "Unauthorized", "srv",
        "WWW-Authenticate: Digest realm=\"chicago4.voip.ms\", nonce=\"n9\", qop=\"auth\", algorithm=MD5\r\n", NULL);
    reset_caps();
    sp_ua_input(ua, r401, strlen(r401));
    CHECK(count_sent("ACK") == 1 && count_sent("INVITE") == 1, "401 -> ACK + one authed INVITE (ack %d inv %d)",
          count_sent("ACK"), count_sent("INVITE"));
    char authed_invite[8192];
    sp_strlcpy(authed_invite, g_last_req, sizeof authed_invite);
    sp_ua_input(ua, r401, strlen(r401));
    CHECK(count_sent("INVITE") == 1, "retransmitted 401 -> still one INVITE, got %d", count_sent("INVITE"));
    CHECK(count_sent("ACK") == 2, "retransmitted 401 re-ACKed, got %d", count_sent("ACK"));
    /* the authed INVITE is still live and can be cancelled (respond to IT,
       not to the re-sent ACK that is now the last request on the wire) */
    sp_strlcpy(g_last_req, authed_invite, sizeof g_last_req);
    feed_response(ua, 180, "Ringing", "p", NULL, NULL);
    reset_caps();
    sp_ua_hangup(ua);
    CHECK(sent_method("CANCEL"), "hangup after auth retry CANCELs the live INVITE, not the completed one");
    free(r401);
    sp_ua_free(ua);
}

static void t_completed_expires(void)
{
    printf("[completed transaction expires after Timer D]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "15550009999");
    feed_response(ua, 100, "Trying", NULL, NULL, NULL);
    feed_response(ua, 486, "Busy Here", "p", NULL, NULL);
    int64_t t = sp_ua_next_timer(ua);
    CHECK(t > 0, "a Timer D deadline is pending");
    int64_t dt = t - sp_now_ms();
    CHECK(dt > 30000 && dt <= 32000 + 50, "deadline ~32 s out (%lld ms)", (long long)dt);
}


static void t_refused_hold_no_491(void)
{
    printf("[refused hold re-INVITE does not 491 the far end afterwards]\n");
    reset_caps();
    sp_ua *ua = make_ua(0);
    sp_ua_dial(ua, "15550007777");
    feed_response(ua, 200, "OK", "p", "Contact: <sip:x@198.51.100.7>\r\n", SDP_ANSWER);
    sp_call_info ci; sp_ua_call(ua, &ci);
    sp_ua_hold(ua, 1);                                  /* our re-INVITE */
    feed_response(ua, 488, "Not Acceptable Here", NULL, NULL, NULL);
    /* far end now re-INVITEs us (same dialog: our local tag is in its To) */
    sp_msg ack; sp_msg_parse(&ack, g_last_req, strlen(g_last_req));
    char ourtag[64] = "";
    sp_param(sp_hdr_get(&ack, "From"), "tag", ourtag, sizeof ourtag);
    const char *cid = sp_hdr_get(&ack, "Call-ID");
    char buf[4096];
    snprintf(buf, sizeof buf,
        "INVITE sip:100000_sub@192.0.2.10:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKfar1\r\n"
        "From: <sip:15550007777@chicago4.voip.ms>;tag=p\r\n"
        "To: <sip:100000_sub@chicago4.voip.ms>;tag=%s\r\n"
        "Call-ID: %s\r\nCSeq: 900 INVITE\r\nContact: <sip:x@198.51.100.7>\r\n"
        "Content-Type: application/sdp\r\nContent-Length: %u\r\n\r\n%s",
        ourtag, cid, (unsigned)strlen(SDP_OFFER), SDP_OFFER);
    sp_msg_free(&ack);
    reset_caps();
    sp_ua_input(ua, buf, strlen(buf));
    CHECK(last_is("200"), "far-end re-INVITE answered 200, not 491 (last tx tag: %s)", g_cap.tx_n ? g_cap.tx_methods[g_cap.tx_n-1] : "-");
    sp_ua_free(ua);
}

static void t_unregister_inflight(void)
{
    printf("[turning SIP off mid-REGISTER really unregisters]\n");
    reset_caps();
    sp_ua *ua = make_ua(1);
    sp_ua_start(ua);
    CHECK(sp_ua_reg_state(ua) == SP_REG_TRYING, "REGISTER in flight");
    reset_caps();
    sp_ua_unregister(ua);
    CHECK(last_is("REGISTER"), "Expires:0 REGISTER sent even though not yet registered");
    const char *ex = last_hdr("Expires");
    CHECK(ex && atoi(ex) == 0, "it is Expires: 0, got %s", ex ? ex : "(none)");
    CHECK(sp_ua_reg_state(ua) == SP_REG_OFF, "state OFF at once");
    feed_response(ua, 401, "Unauthorized", "s", WWW_AUTH, NULL);
    ex = last_hdr("Expires");
    CHECK(last_is("REGISTER") && ex && atoi(ex) == 0, "auth retry keeps Expires: 0");
    feed_response(ua, 200, "OK", NULL, NULL, NULL);
    CHECK(sp_ua_reg_state(ua) == SP_REG_OFF, "still OFF after the 200");
    CHECK(sp_ua_next_refresh(ua) == -1, "no refresh or retry scheduled");
    sp_ua_free(ua);
}

static void t_unreachable(void)
{
    printf("[unreachable server: clear reason, no retries into a dead socket]\n");
    reset_caps();
    sp_ua *ua = make_ua(1);
    sp_ua_start(ua);
    sp_ua_set_unreachable(ua, "Can't reach chicago4.voip.ms (no network?)");
    CHECK(sp_ua_reg_state(ua) == SP_REG_FAILED, "state FAILED");
    CHECK(strstr(sp_ua_reg_detail(ua), "Can't reach") != NULL, "detail says can't reach: %s", sp_ua_reg_detail(ua));
    CHECK(sp_ua_next_refresh(ua) == -1, "no REGISTER retry scheduled");
    CHECK(sp_ua_next_timer(ua) == -1, "no transaction timers left");
    int before = g_cap.changes;
    sp_ua_set_unreachable(ua, "Can't reach chicago4.voip.ms (no network?)");
    CHECK(g_cap.changes == before, "same reason again does not re-publish");
    reset_caps();
    sp_ua_start(ua);                                    /* glue reopened the transport */
    CHECK(sp_ua_reg_state(ua) == SP_REG_TRYING && last_is("REGISTER"), "manual start -> Registering + REGISTER");
    CHECK(strcmp(sp_ua_reg_detail(ua), "Registering") == 0, "detail Registering, got %s", sp_ua_reg_detail(ua));
    sp_ua_free(ua);
}

static void t_retry_keeps_reason(void)
{
    printf("[a failed registration keeps its reason until it recovers]\n");
    reset_caps();
    sp_ua *ua = make_ua(1);
    sp_ua_start(ua);
    feed_response(ua, 403, "Forbidden", "s", NULL, NULL);
    CHECK(sp_ua_reg_state(ua) == SP_REG_FAILED, "403 -> FAILED");
    char why[96];
    sp_strlcpy(why, sp_ua_reg_detail(ua), sizeof why);
    CHECK(strstr(why, "Forbidden") != NULL, "reason kept: %s", why);
    CHECK(sp_ua_next_refresh(ua) > 0, "a retry is scheduled");
    sp_ua_free(ua);
}

int main(void)
{
    sp_log_verbose = 0;       /* keep the harness output readable */
    sp_log_open(NULL);
    t_frame();
    t_sdp();
    t_register();
    t_register_rport();
    t_outgoing();
    t_outgoing_auth();
    t_busy();
    t_cancel();
    t_incoming();
    t_incoming_decline();
    t_glare_busy();
    t_hold();
    t_retrans_final();
    t_retrans_401();
    t_completed_expires();
    t_refused_hold_no_491();
    t_unregister_inflight();
    t_unreachable();
    t_retry_keeps_reason();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

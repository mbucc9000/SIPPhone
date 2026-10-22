/* SIP Phone user agent: registration + one call, RFC 3261 subset tuned for VoIP.ms.
   Sans-IO: the glue feeds received messages in, calls sp_ua_tick() when
   sp_ua_next_timer() comes due, and transmits whatever the send hook gets. */
#ifndef SP_UA_H
#define SP_UA_H

#include <stddef.h>
#include <stdint.h>

enum { SP_TP_UDP = 0, SP_TP_TCP = 1 };

typedef struct {
    char server[128];      /* registrar/proxy host, also the SIP domain */
    int  port;             /* 0 = 5060 */
    int  transport;
    char user[64];
    char auth_user[64];    /* "" = user */
    char password[128];
    char display[64];
    int  do_register;
    int  expires;          /* requested registration lifetime, seconds */
    char user_agent[64];
} sp_cfg;

enum { SP_REG_OFF = 0, SP_REG_TRYING, SP_REG_OK, SP_REG_FAILED };

enum {
    SP_CALL_IDLE = 0,
    SP_CALL_CALLING,       /* outgoing, INVITE sent */
    SP_CALL_RINGING,       /* outgoing, far end ringing (180/183) */
    SP_CALL_INCOMING,      /* incoming, ringing here */
    SP_CALL_ACTIVE,        /* connected */
    SP_CALL_ENDED          /* finished; reason says why */
};

enum { SP_TONE_NONE = 0, SP_TONE_RINGBACK, SP_TONE_BUSY };

typedef struct {
    void *ctx;
    void (*send)(void *ctx, const char *data, size_t len);
    void (*changed)(void *ctx);
    /* on=0 stops media. dir is OUR direction (SP_DIR_*). */
    void (*media)(void *ctx, int on, const char *ip, int port, int pt, int dtmf_pt, int dir);
    void (*tone)(void *ctx, int tone);
} sp_hooks;

typedef struct {
    int  id;
    int  state;
    int  incoming;
    char number[64];       /* user part of the far end's URI */
    char display[96];      /* SIP display name / CNAM, may be empty */
    char reason[96];       /* why it ended (ENDED) */
    int  status;           /* final SIP status when it failed, else 0 */
    long connected_at;     /* wall clock seconds, 0 until connected */
    int  answered;         /* incoming only: 0 at ENDED means missed */
    int  held;             /* we put it on hold */
    int  remote_held;      /* far end put us on hold */
} sp_call_info;

typedef struct sp_ua sp_ua;

sp_ua *sp_ua_new(const sp_hooks *h);
void   sp_ua_free(sp_ua *ua);

void sp_ua_configure(sp_ua *ua, const sp_cfg *cfg);
/* address the transport is bound to (for Via / Contact / SDP) */
void sp_ua_set_local(sp_ua *ua, const char *ip, int port);
void sp_ua_set_rtp_port(sp_ua *ua, int port);

void sp_ua_start(sp_ua *ua);             /* register (if enabled) */
void sp_ua_unregister(sp_ua *ua);        /* expires=0 */
void sp_ua_transport_reset(sp_ua *ua);   /* connection lost: drop transactions */
void sp_ua_refresh_now(sp_ua *ua);       /* re-REGISTER immediately */
/* server unreachable (DNS / no network): FAILED with this reason, no retries
   into a dead socket; the glue reopens the transport and calls sp_ua_start */
void sp_ua_set_unreachable(sp_ua *ua, const char *why);

void    sp_ua_input(sp_ua *ua, const char *data, size_t len);
void    sp_ua_tick(sp_ua *ua);
int64_t sp_ua_next_timer(sp_ua *ua);     /* absolute sp_now_ms(), or -1 */
int64_t sp_ua_next_refresh(sp_ua *ua);   /* absolute ms of the next REGISTER, or -1 */

int  sp_ua_dial(sp_ua *ua, const char *number);   /* call id, or -1 when busy/unconfigured */
int  sp_ua_answer(sp_ua *ua);
void sp_ua_hangup(sp_ua *ua);            /* cancel, decline or BYE as appropriate */
void sp_ua_hold(sp_ua *ua, int on);
void sp_ua_clear_ended(sp_ua *ua);       /* ENDED -> IDLE */

int         sp_ua_reg_state(const sp_ua *ua);
const char *sp_ua_reg_detail(const sp_ua *ua);
int         sp_ua_reg_expires(const sp_ua *ua);
void        sp_ua_call(const sp_ua *ua, sp_call_info *out);
int         sp_ua_busy(const sp_ua *ua);  /* a call is in progress */
const char *sp_ua_public_addr(const sp_ua *ua);

#endif

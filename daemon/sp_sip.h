/* SIP message parsing helpers (RFC 3261 section 7 / 20 / 25, the parts a phone needs). */
#ifndef SP_SIP_H
#define SP_SIP_H

#include <stddef.h>
#include <stdint.h>

#define SP_MAX_HDRS 96

typedef struct {
    const char *name;
    const char *value;
} sp_hdr;

typedef struct {
    char  *raw;           /* owned copy, cut into NUL-terminated pieces */
    int    is_req;
    const char *method;   /* requests */
    const char *ruri;
    int    status;        /* responses */
    const char *reason;
    sp_hdr h[SP_MAX_HDRS];
    int    nh;
    const char *body;
    size_t blen;
} sp_msg;

int  sp_msg_parse(sp_msg *m, const char *data, size_t len);   /* 0 = ok */
void sp_msg_free(sp_msg *m);

/* first header with this name (long or compact form, case-insensitive) */
const char *sp_hdr_get(const sp_msg *m, const char *name);
/* every header line with this name, in order (values not split on commas) */
int sp_hdr_all(const sp_msg *m, const char *name, const char **out, int max);
/* splits a header value on top-level commas (outside quotes and <>) */
int sp_split_commas(const char *v, char out[][320], int max);

/* ;name=value parameter of a header value (after the URI's closing '>' when present).
   Returns 1 when present (value may be empty), 0 when absent. */
int sp_param(const char *hv, const char *name, char *out, size_t n);
/* URI inside <...>, or the bare URI before any ';' */
void sp_hv_uri(const char *hv, char *out, size_t n);
/* display name before '<' with quotes stripped ("" when none) */
void sp_hv_display(const char *hv, char *out, size_t n);
/* user part of a sip:/sips:/tel: URI */
void sp_uri_user(const char *uri, char *out, size_t n);
/* CSeq: number and method */
int sp_cseq(const sp_msg *m, uint32_t *num, char *method, size_t n);
/* top Via's branch parameter */
void sp_top_branch(const sp_msg *m, char *out, size_t n);

/* TCP framing: given buffered stream bytes returns the length of one complete
   message at the front, 0 if more bytes are needed, or -k to skip k bytes of
   keepalive CRLFs. */
long sp_frame(const char *buf, size_t len);

#endif

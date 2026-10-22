/* Minimal SDP offer/answer for one audio stream (RFC 4566 / RFC 3264). */
#ifndef SP_SDP_H
#define SP_SDP_H

#include <stddef.h>
#include <stdint.h>

enum { SP_DIR_SENDRECV = 0, SP_DIR_SENDONLY, SP_DIR_RECVONLY, SP_DIR_INACTIVE };

typedef struct {
    int  ok;
    char ip[64];       /* connection address (media level wins over session level) */
    int  port;         /* 0 = stream rejected */
    int  pts[24];      /* payload types in preference order */
    int  npts;
    int  dtmf_pt;      /* telephone-event/8000, -1 if absent */
    int  dir;          /* as written by the sender of this SDP */
    int  ptime;
} sp_sdp;

int  sp_sdp_parse(const char *body, size_t len, sp_sdp *out);
/* first of our supported payloads (PCMU 0, PCMA 8) present in the remote list, -1 if none */
int  sp_sdp_choose(const sp_sdp *remote);
/* answer direction for a remote direction */
int  sp_sdp_answer_dir(int remote_dir, int local_hold);
void sp_sdp_build(char *out, size_t n, const char *ip, int port, uint32_t sess_id,
                  uint32_t ver, const int *pts, int npts, int dtmf_pt, int dir);
const char *sp_sdp_dir_name(int dir);

#endif

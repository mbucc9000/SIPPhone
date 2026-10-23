/* SIP over TLS for the daemon's SIP TCP socket, via iOS SecureTransport.
   Non-blocking: the handshake and reads/writes are pumped from the poll loop.
   The server certificate is validated against a pinned anchor (ISRG Root X1),
   because iOS 6's trust store predates Let's Encrypt. Host builds stub this out. */
#ifndef SP_TLS_H
#define SP_TLS_H

#include <stddef.h>

typedef struct sp_tls sp_tls;

/* Wrap an already-connected non-blocking TCP fd. host is checked against the
   certificate. Returns NULL on failure. */
sp_tls *sp_tls_new(int fd, const char *host);
void    sp_tls_free(sp_tls *t);

/* Drive the handshake: 1 = done (verified), 0 = needs more I/O (call again when
   the socket is readable/writable), -1 = failed (untrusted cert, wrong host, or
   transport error). */
int sp_tls_handshake(sp_tls *t);

/* After the handshake: like recv/send. >0 bytes, 0 = would block, -1 = closed/error. */
int sp_tls_read(sp_tls *t, void *buf, size_t n);
int sp_tls_write(sp_tls *t, const void *buf, size_t n);

#endif

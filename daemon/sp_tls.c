#include "sp_tls.h"
#include "sp_util.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifdef __APPLE__
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include "sp_tls_anchor.h"

struct sp_tls {
    SSLContextRef ssl;
    int fd;
    int verified;
};

/* SecureTransport I/O over our non-blocking fd. errSSLWouldBlock keeps partial
   progress; SecureTransport retries with the same request. */
static OSStatus tls_read(SSLConnectionRef conn, void *data, size_t *len)
{
    int fd = (int)(intptr_t)conn;
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t r = read(fd, (char *)data + got, want - got);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        *len = got;
        if (r == 0)
            return errSSLClosedGraceful;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return errSSLWouldBlock;
        if (errno == EINTR)
            continue;
        return errSSLClosedAbort;
    }
    *len = got;
    return noErr;
}

static OSStatus tls_write(SSLConnectionRef conn, const void *data, size_t *len)
{
    int fd = (int)(intptr_t)conn;
    size_t want = *len, put = 0;
    while (put < want) {
        ssize_t r = write(fd, (const char *)data + put, want - put);
        if (r > 0) {
            put += (size_t)r;
            continue;
        }
        *len = put;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return errSSLWouldBlock;
        if (errno == EINTR)
            continue;
        return errSSLClosedAbort;
    }
    *len = put;
    return noErr;
}

sp_tls *sp_tls_new(int fd, const char *host)
{
    sp_tls *t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->fd = fd;
    t->ssl = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!t->ssl) {
        free(t);
        return NULL;
    }
    SSLSetIOFuncs(t->ssl, tls_read, tls_write);
    SSLSetConnection(t->ssl, (SSLConnectionRef)(intptr_t)fd);
    if (host && host[0])
        SSLSetPeerDomainName(t->ssl, host, strlen(host));
    SSLSetProtocolVersionMin(t->ssl, kTLSProtocol1);
    /* evaluate trust ourselves so we can pin the anchor iOS 6 doesn't ship */
    SSLSetSessionOption(t->ssl, kSSLSessionOptionBreakOnServerAuth, true);
    return t;
}

/* Validate the server chain against the pinned ISRG Root X1 and the host name
   (the SSL policy carried by the trust object from SSLSetPeerDomainName). */
static int verify_peer(sp_tls *t)
{
    SecTrustRef trust = NULL;
    if (SSLCopyPeerTrust(t->ssl, &trust) != noErr || !trust)
        return 0;
    int ok = 0;
    CFDataRef der = CFDataCreate(NULL, SP_ISRG_ROOT_X1, (CFIndex)sizeof SP_ISRG_ROOT_X1);
    SecCertificateRef anchor = der ? SecCertificateCreateWithData(NULL, der) : NULL;
    if (anchor) {
        const void *arr[1] = { anchor };
        CFArrayRef anchors = CFArrayCreate(NULL, arr, 1, &kCFTypeArrayCallBacks);
        if (anchors) {
            SecTrustSetAnchorCertificates(trust, anchors);
            SecTrustSetAnchorCertificatesOnly(trust, true);   /* ONLY our anchor is trusted */
            SecTrustResultType res = kSecTrustResultInvalid;
            if (SecTrustEvaluate(trust, &res) == errSecSuccess &&
                (res == kSecTrustResultUnspecified || res == kSecTrustResultProceed))
                ok = 1;
            CFRelease(anchors);
        }
        CFRelease(anchor);
    }
    if (der)
        CFRelease(der);
    CFRelease(trust);
    return ok;
}

int sp_tls_handshake(sp_tls *t)
{
    for (;;) {
        OSStatus s = SSLHandshake(t->ssl);
        if (s == noErr)
            return t->verified ? 1 : -1;          /* must have passed our trust check */
        if (s == errSSLWouldBlock)
            return 0;
        if (s == errSSLPeerAuthCompleted) {
            if (!verify_peer(t)) {
                sp_log("tls: server certificate not trusted, refusing");
                return -1;
            }
            t->verified = 1;
            continue;                             /* resume the handshake */
        }
        sp_log("tls: handshake failed (%d)", (int)s);
        return -1;
    }
}

int sp_tls_read(sp_tls *t, void *buf, size_t n)
{
    size_t got = 0;
    OSStatus s = SSLRead(t->ssl, buf, n, &got);
    if (got > 0)
        return (int)got;
    if (s == errSSLWouldBlock)
        return 0;
    return -1;
}

int sp_tls_write(sp_tls *t, const void *buf, size_t n)
{
    size_t put = 0;
    OSStatus s = SSLWrite(t->ssl, buf, n, &put);
    if (put > 0)
        return (int)put;
    if (s == errSSLWouldBlock)
        return 0;
    return -1;
}

void sp_tls_free(sp_tls *t)
{
    if (!t)
        return;
    if (t->ssl) {
        SSLClose(t->ssl);
        CFRelease(t->ssl);
    }
    free(t);
}

#else  /* host build: no TLS, fail closed */

struct sp_tls { int fd; };
sp_tls *sp_tls_new(int fd, const char *host) { (void)fd; (void)host; return NULL; }
void sp_tls_free(sp_tls *t) { free(t); }
int sp_tls_handshake(sp_tls *t) { (void)t; return -1; }
int sp_tls_read(sp_tls *t, void *buf, size_t n) { (void)t; (void)buf; (void)n; return -1; }
int sp_tls_write(sp_tls *t, const void *buf, size_t n) { (void)t; (void)buf; (void)n; return -1; }

#endif

/* SIP Phone: small portable helpers (time, random, logging, string buffers).
   Everything in sp_*.c is plain C so it builds on Linux for the test harness. */
#ifndef SP_UTIL_H
#define SP_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

int64_t  sp_now_ms(void);          /* monotonic milliseconds */
uint32_t sp_rand32(void);
void     sp_rand_hex(char *out, int nchars);   /* nchars hex digits + NUL */
void     sp_rand_bytes(uint8_t *out, size_t n);  /* CSPRNG bytes (keys/salts) */

/* Log sink. The daemon points it at a file; tests leave it on stderr. */
void sp_log_open(const char *path);
void sp_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void sp_log_block(const char *prefix, const char *data, size_t len);  /* multi-line, redacts auth */
extern int sp_log_verbose;

/* growable string buffer */
typedef struct {
    char  *s;
    size_t len, cap;
} sp_buf;

void sp_buf_init(sp_buf *b);
void sp_buf_free(sp_buf *b);
void sp_buf_add(sp_buf *b, const char *s, size_t n);
void sp_buf_puts(sp_buf *b, const char *s);
void sp_buf_printf(sp_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
char *sp_buf_take(sp_buf *b);     /* hands ownership of s to the caller */

/* bounded copy that always terminates */
void sp_strlcpy(char *dst, const char *src, size_t n);
int  sp_strcaseeq(const char *a, const char *b);
int  sp_strncaseeq(const char *a, const char *b, size_t n);
char *sp_strdup_n(const char *s, size_t n);

#endif

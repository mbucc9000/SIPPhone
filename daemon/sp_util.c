#ifdef _WIN32
#define _CRT_RAND_S
#endif

#include "sp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#define SP_MU CRITICAL_SECTION
#define SP_MU_INIT(m) InitializeCriticalSection(m)
#define SP_LOCK(m) EnterCriticalSection(m)
#define SP_UNLOCK(m) LeaveCriticalSection(m)
static void localtime_r(const time_t *t, struct tm *tm) { localtime_s(tm, t); }
#else
#include <sys/time.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#define SP_MU pthread_mutex_t
#define SP_MU_INIT(m) pthread_mutex_init(m, NULL)
#define SP_LOCK(m) pthread_mutex_lock(m)
#define SP_UNLOCK(m) pthread_mutex_unlock(m)
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif
#endif

int sp_log_verbose = 1;

int64_t sp_now_ms(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER t;
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (int64_t)(t.QuadPart * 1000 / freq.QuadPart);
#elif defined(__APPLE__)
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0)
        mach_timebase_info(&tb);
    uint64_t t = mach_absolute_time();
    return (int64_t)(t / 1000000ULL * tb.numer / tb.denom);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

uint32_t sp_rand32(void)
{
#ifdef _WIN32
    unsigned int v = 0;
    if (rand_s(&v) != 0)
        v = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
    return v;
#elif defined(__APPLE__)
    return arc4random();
#else
    static int fd = -2;
    uint32_t v = 0;
    if (fd == -2)
        fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, &v, sizeof v) != (ssize_t)sizeof v)
        v = (uint32_t)random() ^ ((uint32_t)random() << 16);
    return v;
#endif
}

void sp_rand_hex(char *out, int nchars)
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < nchars; i++)
        out[i] = hx[sp_rand32() & 15];
    out[nchars] = 0;
}

void sp_rand_bytes(uint8_t *out, size_t n)
{
#if defined(__APPLE__)
    arc4random_buf(out, n);                  /* CSPRNG, seeded by the kernel */
#else
    size_t i = 0;
    while (i < n) {
        uint32_t v = sp_rand32();
        for (int b = 0; b < 4 && i < n; b++)
            out[i++] = (uint8_t)(v >> (8 * b));
    }
#endif
}

/* ---- log ---- */

static FILE *g_log;
static char g_log_path[512];
static SP_MU g_log_mu;
static int g_log_mu_ready;

static void log_lock(void)
{
    if (!g_log_mu_ready) {
        SP_MU_INIT(&g_log_mu);
        g_log_mu_ready = 1;
    }
    SP_LOCK(&g_log_mu);
}

static void log_unlock(void)
{
    SP_UNLOCK(&g_log_mu);
}

void sp_log_open(const char *path)
{
    log_lock();
    if (g_log && g_log != stderr)
        fclose(g_log);
    sp_strlcpy(g_log_path, path ? path : "", sizeof g_log_path);
    g_log = path ? fopen(path, "a") : NULL;
#ifndef _WIN32
    if (g_log)
        chmod(path, 0600);               /* call history lives in here: root only */
#endif
    log_unlock();
}

static void log_rotate_locked(void)
{
    struct stat st;
    if (!g_log || g_log == stderr || !g_log_path[0])
        return;
    if (stat(g_log_path, &st) != 0 || st.st_size < 768 * 1024)
        return;
    char old[600];
    snprintf(old, sizeof old, "%s.1", g_log_path);
    fclose(g_log);
    rename(g_log_path, old);
    g_log = fopen(g_log_path, "a");
#ifndef _WIN32
    if (g_log)
        chmod(g_log_path, 0600);
#endif
}

static void log_prefix(FILE *f)
{
#ifdef _WIN32
    time_t now = time(NULL);
    int ms = (int)(sp_now_ms() % 1000);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);           /* wall-clock ms, so lines sort correctly */
    time_t now = tv.tv_sec;
    int ms = (int)(tv.tv_usec / 1000);
#endif
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(f, "%02d-%02d %02d:%02d:%02d.%03d ", tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

void sp_log(const char *fmt, ...)
{
    log_lock();
    FILE *f = g_log ? g_log : stderr;
    log_rotate_locked();
    f = g_log ? g_log : stderr;
    log_prefix(f);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fflush(f);
    log_unlock();
}

/* Logs a SIP message line by line. Authorization headers are cut down to the
   username so the digest response never lands in the log. */
void sp_log_block(const char *prefix, const char *data, size_t len)
{
    if (!sp_log_verbose) {
        const char *e = memchr(data, '\r', len);
        size_t n = e ? (size_t)(e - data) : (len > 120 ? 120 : len);
        sp_log("%s %.*s", prefix, (int)n, data);
        return;
    }
    log_lock();
    log_rotate_locked();
    FILE *f = g_log ? g_log : stderr;
    log_prefix(f);
    fprintf(f, "%s (%u bytes)\n", prefix, (unsigned)len);
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && data[j] != '\n')
            j++;
        size_t n = j - i;
        if (n && data[i + n - 1] == '\r')
            n--;
        if ((n > 14 && sp_strncaseeq(data + i, "Authorization:", 14)) ||
            (n > 20 && sp_strncaseeq(data + i, "Proxy-Authorization:", 20)))
            fprintf(f, "    | %.*s: Digest (redacted)\n",
                    data[i] == 'P' || data[i] == 'p' ? 19 : 13, data + i);
        else
            fprintf(f, "    | %.*s\n", (int)n, data + i);
        i = j + 1;
    }
    fflush(f);
    log_unlock();
}

/* ---- buffers ---- */

void sp_buf_init(sp_buf *b)
{
    b->s = NULL;
    b->len = b->cap = 0;
}

void sp_buf_free(sp_buf *b)
{
    free(b->s);
    sp_buf_init(b);
}

static void buf_reserve(sp_buf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap)
        return;
    size_t nc = b->cap ? b->cap * 2 : 256;
    while (nc < b->len + extra + 1)
        nc *= 2;
    b->s = realloc(b->s, nc);
    b->cap = nc;
}

void sp_buf_add(sp_buf *b, const char *s, size_t n)
{
    buf_reserve(b, n);
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = 0;
}

void sp_buf_puts(sp_buf *b, const char *s)
{
    sp_buf_add(b, s, strlen(s));
}

void sp_buf_printf(sp_buf *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n < sizeof tmp) {
        sp_buf_add(b, tmp, (size_t)n);
        return;
    }
    buf_reserve(b, (size_t)n);
    va_start(ap, fmt);
    vsnprintf(b->s + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
}

char *sp_buf_take(sp_buf *b)
{
    char *s = b->s;
    if (!s)
        s = calloc(1, 1);
    sp_buf_init(b);
    return s;
}

void sp_strlcpy(char *dst, const char *src, size_t n)
{
    if (!n)
        return;
    size_t i = 0;
    if (src)
        for (; i + 1 < n && src[i]; i++)
            dst[i] = src[i];
    dst[i] = 0;
}

int sp_strcaseeq(const char *a, const char *b)
{
    for (;; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        if (!*a)
            return 1;
    }
}

int sp_strncaseeq(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
        if (!a[i])
            return 1;
    }
    return 1;
}

char *sp_strdup_n(const char *s, size_t n)
{
    char *d = malloc(n + 1);
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}

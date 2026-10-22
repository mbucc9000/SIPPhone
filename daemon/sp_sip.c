#include "sp_sip.h"
#include "sp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const struct {
    char c;
    const char *name;
} kCompact[] = {
    { 'v', "Via" }, { 'f', "From" }, { 't', "To" }, { 'i', "Call-ID" },
    { 'm', "Contact" }, { 'l', "Content-Length" }, { 'c', "Content-Type" },
    { 'k', "Supported" }, { 'e', "Content-Encoding" }, { 's', "Subject" },
    { 'o', "Event" }, { 'u', "Allow-Events" }, { 'r', "Refer-To" },
};

static const char *canon_name(const char *n)
{
    if (n[0] && !n[1])
        for (size_t i = 0; i < sizeof kCompact / sizeof kCompact[0]; i++)
            if (tolower((unsigned char)n[0]) == kCompact[i].c)
                return kCompact[i].name;
    return n;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = 0;
    return s;
}

int sp_msg_parse(sp_msg *m, const char *data, size_t len)
{
    memset(m, 0, sizeof *m);
    m->raw = sp_strdup_n(data, len);
    char *p = m->raw;
    char *end = m->raw + len;

    /* header block ends at the first blank line */
    char *hend = strstr(p, "\r\n\r\n");
    size_t sep = 4;
    if (!hend) {
        hend = strstr(p, "\n\n");
        sep = 2;
    }
    char *body = hend ? hend + sep : end;
    if (hend)
        *hend = 0;

    /* start line */
    char *nl = strchr(p, '\n');
    if (nl)
        *nl = 0;
    char *line = trim(p);
    if (strncmp(line, "SIP/2.0 ", 8) == 0) {
        m->is_req = 0;
        m->status = atoi(line + 8);
        char *r = strchr(line + 8, ' ');
        m->reason = r ? trim(r + 1) : "";
        if (m->status < 100 || m->status > 699)
            goto bad;
    } else {
        m->is_req = 1;
        char *sp1 = strchr(line, ' ');
        if (!sp1)
            goto bad;
        *sp1 = 0;
        char *sp2 = strchr(sp1 + 1, ' ');
        if (!sp2 || strncmp(sp2 + 1, "SIP/2.0", 7) != 0)
            goto bad;
        *sp2 = 0;
        m->method = line;
        m->ruri = sp1 + 1;
    }
    p = nl ? nl + 1 : body;

    /* headers, unfolding continuation lines */
    while (p && p < body && *p) {
        nl = strchr(p, '\n');
        char *next = nl ? nl + 1 : NULL;
        while (next && (*next == ' ' || *next == '\t')) {
            /* folded line: join */
            *nl = ' ';
            if (nl > p && nl[-1] == '\r')
                nl[-1] = ' ';
            nl = strchr(next, '\n');
            next = nl ? nl + 1 : NULL;
        }
        if (nl)
            *nl = 0;
        char *colon = strchr(p, ':');
        if (colon && m->nh < SP_MAX_HDRS) {
            *colon = 0;
            char *name = trim(p);
            m->h[m->nh].name = canon_name(name);
            m->h[m->nh].value = trim(colon + 1);
            m->nh++;
        }
        p = next;
    }

    const char *cl = sp_hdr_get(m, "Content-Length");
    size_t avail = (size_t)(end - body);
    if (hend && cl) {
        long n = atol(cl);
        if (n < 0)
            n = 0;
        m->blen = (size_t)n < avail ? (size_t)n : avail;
    } else {
        m->blen = hend ? avail : 0;
    }
    m->body = body;
    if (hend)
        body[m->blen] = 0;
    return 0;
bad:
    free(m->raw);
    m->raw = NULL;
    return -1;
}

void sp_msg_free(sp_msg *m)
{
    free(m->raw);
    memset(m, 0, sizeof *m);
}

const char *sp_hdr_get(const sp_msg *m, const char *name)
{
    name = canon_name(name);
    for (int i = 0; i < m->nh; i++)
        if (sp_strcaseeq(m->h[i].name, name))
            return m->h[i].value;
    return NULL;
}

int sp_hdr_all(const sp_msg *m, const char *name, const char **out, int max)
{
    name = canon_name(name);
    int k = 0;
    for (int i = 0; i < m->nh && k < max; i++)
        if (sp_strcaseeq(m->h[i].name, name))
            out[k++] = m->h[i].value;
    return k;
}

int sp_split_commas(const char *v, char out[][320], int max)
{
    int k = 0, q = 0, ang = 0;
    const char *s = v;
    for (const char *p = v;; p++) {
        char c = *p;
        if (c == '"' && (p == v || p[-1] != '\\'))
            q = !q;
        else if (!q && c == '<')
            ang++;
        else if (!q && c == '>' && ang)
            ang--;
        if (c == 0 || (c == ',' && !q && !ang)) {
            if (k < max) {
                size_t n = (size_t)(p - s);
                while (n && (*s == ' ' || *s == '\t')) {
                    s++;
                    n--;
                }
                while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
                    n--;
                if (n >= 320)
                    n = 319;
                if (n) {
                    memcpy(out[k], s, n);
                    out[k][n] = 0;
                    k++;
                }
            }
            if (!c)
                break;
            s = p + 1;
        }
    }
    return k;
}

int sp_param(const char *hv, const char *name, char *out, size_t n)
{
    if (out && n)
        out[0] = 0;
    if (!hv)
        return 0;
    const char *p = hv;
    const char *gt = NULL;
    /* skip a quoted display name, then the <uri> */
    const char *lt = NULL;
    int q = 0;
    for (const char *s = hv; *s; s++) {
        if (*s == '"' && (s == hv || s[-1] != '\\'))
            q = !q;
        else if (!q && *s == '<') {
            lt = s;
            break;
        }
    }
    if (lt) {
        gt = strchr(lt, '>');
        p = gt ? gt + 1 : lt;
    }
    size_t nl = strlen(name);
    while ((p = strchr(p, ';'))) {
        p++;
        while (*p == ' ')
            p++;
        if (sp_strncaseeq(p, name, nl) && (p[nl] == '=' || p[nl] == ';' || p[nl] == 0 ||
                                           p[nl] == ' ' || p[nl] == ',')) {
            if (p[nl] != '=')
                return 1;
            const char *v = p + nl + 1;
            size_t vl = 0;
            if (*v == '"') {
                v++;
                while (v[vl] && v[vl] != '"')
                    vl++;
            } else {
                while (v[vl] && v[vl] != ';' && v[vl] != ',' && v[vl] != ' ' && v[vl] != '>')
                    vl++;
            }
            if (out && n) {
                if (vl >= n)
                    vl = n - 1;
                memcpy(out, v, vl);
                out[vl] = 0;
            }
            return 1;
        }
    }
    return 0;
}

void sp_hv_uri(const char *hv, char *out, size_t n)
{
    out[0] = 0;
    if (!hv)
        return;
    const char *lt = strchr(hv, '<');
    if (lt) {
        const char *gt = strchr(lt, '>');
        size_t l = gt ? (size_t)(gt - lt - 1) : strlen(lt + 1);
        if (l >= n)
            l = n - 1;
        memcpy(out, lt + 1, l);
        out[l] = 0;
        return;
    }
    while (*hv == ' ')
        hv++;
    size_t l = strcspn(hv, "; ,");
    if (l >= n)
        l = n - 1;
    memcpy(out, hv, l);
    out[l] = 0;
}

void sp_hv_display(const char *hv, char *out, size_t n)
{
    out[0] = 0;
    if (!hv)
        return;
    const char *lt = strchr(hv, '<');
    if (!lt)
        return;
    const char *s = hv;
    while (s < lt && (*s == ' ' || *s == '\t'))
        s++;
    const char *e = lt;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
        e--;
    if (e - s >= 2 && *s == '"' && e[-1] == '"') {
        s++;
        e--;
    }
    size_t l = (size_t)(e - s);
    if (l >= n)
        l = n - 1;
    size_t k = 0;
    for (size_t i = 0; i < l; i++) {
        if (s[i] == '\\' && i + 1 < l)
            i++;
        out[k++] = s[i];
    }
    out[k] = 0;
}

void sp_uri_user(const char *uri, char *out, size_t n)
{
    out[0] = 0;
    const char *p = uri;
    if (sp_strncaseeq(p, "sips:", 5))
        p += 5;
    else if (sp_strncaseeq(p, "sip:", 4))
        p += 4;
    else if (sp_strncaseeq(p, "tel:", 4)) {
        p += 4;
        size_t l = strcspn(p, ";");
        if (l >= n)
            l = n - 1;
        memcpy(out, p, l);
        out[l] = 0;
        return;
    }
    const char *at = strchr(p, '@');
    if (!at)
        return;
    size_t l = (size_t)(at - p);
    const char *semi = memchr(p, ';', l);   /* user params */
    if (semi)
        l = (size_t)(semi - p);
    const char *colon = memchr(p, ':', l);  /* user:password */
    if (colon)
        l = (size_t)(colon - p);
    if (l >= n)
        l = n - 1;
    /* undo %XX escapes */
    size_t k = 0;
    for (size_t i = 0; i < l && k + 1 < n; i++) {
        if (p[i] == '%' && i + 2 < l && isxdigit((unsigned char)p[i + 1]) &&
            isxdigit((unsigned char)p[i + 2])) {
            char hx[3] = { p[i + 1], p[i + 2], 0 };
            out[k++] = (char)strtol(hx, NULL, 16);
            i += 2;
        } else {
            out[k++] = p[i];
        }
    }
    out[k] = 0;
}

int sp_cseq(const sp_msg *m, uint32_t *num, char *method, size_t n)
{
    const char *v = sp_hdr_get(m, "CSeq");
    if (!v)
        return -1;
    char *e;
    unsigned long x = strtoul(v, &e, 10);
    while (*e == ' ')
        e++;
    if (num)
        *num = (uint32_t)x;
    if (method)
        sp_strlcpy(method, e, n);
    return 0;
}

void sp_top_branch(const sp_msg *m, char *out, size_t n)
{
    out[0] = 0;
    const char *v = sp_hdr_get(m, "Via");
    if (!v)
        return;
    /* only the first comma element */
    char first[1][320];
    if (sp_split_commas(v, first, 1) < 1)
        return;
    sp_param(first[0], "branch", out, n);
}

long sp_frame(const char *buf, size_t len)
{
    size_t i = 0;
    while (i < len && (buf[i] == '\r' || buf[i] == '\n'))
        i++;
    if (i)
        return -(long)i;
    /* find end of headers */
    const char *hend = NULL;
    for (size_t k = 0; k + 3 < len; k++)
        if (buf[k] == '\r' && buf[k + 1] == '\n' && buf[k + 2] == '\r' && buf[k + 3] == '\n') {
            hend = buf + k + 4;
            break;
        }
    if (!hend)
        return len > 65536 ? -(long)len : 0;   /* garbage: drop it */
    size_t hlen = (size_t)(hend - buf);
    /* Content-Length (or l:) at a line start */
    long cl = 0;
    for (size_t k = 0; k < hlen; k++) {
        if (k && buf[k - 1] != '\n')
            continue;
        if (sp_strncaseeq(buf + k, "Content-Length", 14) || ((buf[k] == 'l' || buf[k] == 'L') &&
                                                             (buf[k + 1] == ':' || buf[k + 1] == ' '))) {
            const char *c = memchr(buf + k, ':', hlen - k);
            if (c) {
                cl = atol(c + 1);
                break;
            }
        }
    }
    if (cl < 0)
        cl = 0;
    if (hlen + (size_t)cl > len)
        return 0;
    return (long)(hlen + (size_t)cl);
}

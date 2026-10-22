#import "SPClient.h"
#import "sp_proto.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

@implementation SPClient {
    NSString *_regDetail, *_callNumber, *_callDisplay, *_callReason;
}

+ (SPClient *)shared
{
    static SPClient *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [SPClient new]; });
    return s;
}

- (id)init
{
    if ((self = [super init])) {
        _regDetail = @"";
        _callNumber = @"";
        _callDisplay = @"";
        _callReason = @"";
        [self refresh];
    }
    return self;
}

/* Open a short-lived connection, write one command line, close. The daemon
   publishes state asynchronously, so we don't need to hold the socket. */
- (BOOL)send:(NSString *)cmd
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return NO;
    /* This runs inside SpringBoard and MobilePhone: a daemon that dies mid-write
       must not SIGPIPE them, and a wedged daemon must not freeze their UI. */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SP_SOCK_PATH, sizeof sa.sun_path - 1);
    BOOL ok = NO;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
        NSData *d = [[cmd stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        ssize_t off = 0, n = (ssize_t)d.length;
        const char *p = d.bytes;
        while (off < n) {
            ssize_t w = write(fd, p + off, (size_t)(n - off));
            if (w <= 0)
                break;
            off += w;
        }
        ok = off == n;
    }
    close(fd);
    return ok;
}

- (BOOL)dial:(NSString *)number { return [self send:[@"DIAL " stringByAppendingString:number ?: @""]]; }
- (void)answer { [self send:@"ANSWER"]; }
- (void)hangup { [self send:@"HANGUP"]; }
- (void)setHold:(BOOL)on { [self send:[NSString stringWithFormat:@"HOLD %d", on ? 1 : 0]]; }
- (void)setMute:(BOOL)on { [self send:[NSString stringWithFormat:@"MUTE %d", on ? 1 : 0]]; }
- (void)setSpeaker:(BOOL)on { [self send:[NSString stringWithFormat:@"SPEAKER %d", on ? 1 : 0]]; }
- (void)sendDTMF:(NSString *)digit { [self send:[@"DTMF " stringByAppendingString:digit ?: @""]]; }
- (void)reloadPrefs { [self send:@"RELOAD"]; }

static int ival(NSDictionary *d, NSString *k) { id v = d[k]; return [v respondsToSelector:@selector(intValue)] ? [v intValue] : 0; }
static NSString *sval(NSDictionary *d, NSString *k) { id v = d[k]; return [v isKindOfClass:[NSString class]] ? v : @""; }

- (void)refresh
{
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@SP_STATE_PATH];
    _regState = ival(d, @SP_K_REG_STATE);
    _regDetail = sval(d, @SP_K_REG_DETAIL);
    _callState = ival(d, @SP_K_CALL_STATE);
    _callIncoming = ival(d, @SP_K_CALL_INCOMING) != 0;
    _callNumber = sval(d, @SP_K_CALL_NUMBER);
    _callDisplay = sval(d, @SP_K_CALL_DISPLAY);
    _callReason = sval(d, @SP_K_CALL_REASON);
    _muted = ival(d, @SP_K_CALL_MUTED) != 0;
    _held = ival(d, @SP_K_CALL_HELD) != 0;
    _speaker = ival(d, @SP_K_CALL_SPEAKER) != 0;
    _callStart = (long)ival(d, @SP_K_CALL_START);
    _callId = ival(d, @SP_K_CALL_ID);
}

- (NSString *)regDetail { return _regDetail; }
- (NSString *)callNumber { return _callNumber; }
- (NSString *)callDisplay { return _callDisplay; }
- (NSString *)callReason { return _callReason; }

- (BOOL)routingEnabled
{
    NSDictionary *p = [NSDictionary dictionaryWithContentsOfFile:@SP_PREFS_PATH];
    if (!p)
        return NO;
    BOOL enabled = ival(p, @SP_PK_ENABLED) != 0;
    BOOL routeAll = p[@SP_PK_ROUTEALL] ? (ival(p, @SP_PK_ROUTEALL) != 0) : YES;
    NSString *server = sval(p, @SP_PK_SERVER);
    NSString *user = sval(p, @SP_PK_USER);
    return enabled && routeAll && server.length && user.length;
}

- (NSString *)notReadyReason
{
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@SP_STATE_PATH];
    if (!d)
        return @"The SIP Phone service isn't running. Try again in a few seconds, or reboot.";
    int reg = ival(d, @SP_K_REG_STATE);
    if (reg == SPUI_REG_OK)
        return nil;                     /* refreshes never leave OK, so this is the only "ready" */
    if (reg == SPUI_REG_TRYING)
        return @"Still connecting to your SIP server. Try again in a few seconds.";
    NSString *detail = sval(d, @SP_K_REG_DETAIL);
    return detail.length ? detail : @"Not registered with your SIP server.";
}
@end

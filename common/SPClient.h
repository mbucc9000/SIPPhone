/* Thin client the Phone and SpringBoard tweaks use to drive sipphoned:
   connect to the control socket, send commands, read the published state. */
#import <Foundation/Foundation.h>

@interface SPClient : NSObject
+ (SPClient *)shared;

/* commands (dial reports whether the daemon actually took it) */
- (BOOL)dial:(NSString *)number;
- (void)answer;
- (void)hangup;
- (void)setHold:(BOOL)on;
- (void)setMute:(BOOL)on;
- (void)setSpeaker:(BOOL)on;
- (void)sendDTMF:(NSString *)digit;
- (void)reloadPrefs;

/* current published state (re-read from the state plist) */
- (void)refresh;
@property (nonatomic, readonly) int regState;
@property (nonatomic, readonly) NSString *regDetail;
@property (nonatomic, readonly) int callState;
@property (nonatomic, readonly) BOOL callIncoming;
@property (nonatomic, readonly) NSString *callNumber;
@property (nonatomic, readonly) NSString *callDisplay;
@property (nonatomic, readonly) NSString *callReason;
@property (nonatomic, readonly) BOOL muted;
@property (nonatomic, readonly) BOOL held;
@property (nonatomic, readonly) BOOL speaker;
@property (nonatomic, readonly) long callStart;    /* unix seconds, 0 until connected */
@property (nonatomic, readonly) int callId;

/* are we configured + enabled for SIP routing right now? */
- (BOOL)routingEnabled;
/* why a SIP call can't be placed right now, or nil when it can */
- (NSString *)notReadyReason;
@end

/* mirror of sp_ua.h call states so the UI doesn't need the C header */
enum { SPUI_IDLE = 0, SPUI_CALLING, SPUI_RINGING, SPUI_INCOMING, SPUI_ACTIVE, SPUI_ENDED };
enum { SPUI_REG_OFF = 0, SPUI_REG_TRYING, SPUI_REG_OK, SPUI_REG_FAILED };

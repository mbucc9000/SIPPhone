/* SIPPhone — SpringBoard hook: the SIP call screen.
   Built from iOS 6's own parts so it looks like the stock in-call screen:
   TelephonyUI's LCD bar, End Call bar, Decline/Answer bar, slide-to-answer bar
   and keypad (SpringBoard already links TelephonyUI), plus the Phone app's own
   six-button panel artwork. Every class and selector below was checked against
   the iOS 6.1.2 SpringBoard / TelephonyUI / SpringBoardUI dumps from this device.
   It lives in SpringBoard (not the Phone app) so it works from any app and on
   the lock screen; it observes the daemon's published state. */
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <AVFoundation/AVFoundation.h>
#import <AddressBook/AddressBook.h>
#import <notify.h>
#import "SPClient.h"
#import "sp_proto.h"

/* ---- TelephonyUI (iOS 6.1.2) ---- */
@interface TPLCDBar : UIImageView
+ (float)defaultHeight;
@end
@interface TPLCDView : TPLCDBar
- (id)initWithDefaultSizeForOrientation:(int)orientation;
- (void)setText:(NSString *)text;
- (void)setLabel:(NSString *)label;
- (void)setLayoutAsLabelled:(BOOL)labelled;
@end
@interface TPBottomBar : UIView
+ (float)defaultHeight;
@end
@interface TPBottomSingleButtonBar : TPBottomBar
- (id)initForEndCallWithFrame:(CGRect)frame;
- (UIButton *)button;
@end
@interface TPBottomDoubleButtonBar : TPBottomSingleButtonBar
- (id)initForIncomingCallWithFrame:(CGRect)frame;
- (UIButton *)button2;
@end
@interface TPBottomLockBar : TPBottomBar
- (id)initForIncomingCallWithFrame:(CGRect)frame;
- (void)setDelegate:(id)delegate;
- (void)setLabel:(NSString *)label;     /* the track text is only created by setLabel: */
- (BOOL)isAnimating;
- (void)startAnimating;
- (void)stopAnimating;
- (void)relock;
@end
@interface TPPhonePad : UIControl
- (void)setDelegate:(id)delegate;
- (void)setPlaysSounds:(BOOL)plays;
@end

/* ---- SpringBoardUI: SpringBoard's own sound player; "Ringtone" category =
   Ringer volume and route, works after a respring (unlike SBUserAgent's ring,
   which needs the telephony ringer that only a cellular call creates) ---- */
@interface SBWallpaperView : UIView
- (id)initWithOrientation:(int)orientation variant:(int)variant;   /* variant 0 = lock screen */
@end
@interface SBUISound : NSObject
- (id)initWithRingtone:(NSString *)identifier vibrationPattern:(NSDictionary *)pattern
               repeats:(BOOL)repeats audioCategory:(NSString *)category;
- (BOOL)play;
- (void)stop;
@end

/* ---- SpringBoard (iOS 6.1.2) ---- */
@interface SBAwayController : NSObject
+ (id)sharedAwayController;
- (BOOL)isLocked;
- (BOOL)isDimmed;
- (void)undimScreen;
- (void)cancelDimTimer;
- (void)restartDimTimer;
@end
/* The ringer switch lives on SBMediaController; SBSoundPreferences is
   SpringBoard's own source for the ringtone and Vibrate on Ring/Silent. */
@interface SBMediaController : NSObject
+ (id)sharedInstance;
- (BOOL)isRingerMuted;
@end
@interface SBSoundPreferences : NSObject
+ (NSString *)ringtonePath;
+ (NSString *)ringtoneIdentifier;
+ (BOOL)shouldVibrateForCurrentRingerState;
@end
@interface TLToneManager : NSObject
+ (id)sharedRingtoneManager;
- (NSString *)copyPathOfRingtoneWithIdentifier:(id)identifier;
- (id)currentRingtoneIdentifier;
- (NSString *)defaultRingtonePath;
@end
@interface SpringBoard : UIApplication
- (void)resetIdleTimerAndUndim:(BOOL)undim;
- (void)undim;                                   /* turns the backlight back on */
- (void)setBacklightFactor:(float)factor;
- (void)cancelSetBacklightFactorToZeroAfterDelay;
- (void)setIdleTimerDisabled:(BOOL)disabled forReason:(NSString *)reason;
@end

/* ------------------------------------------------------------------ helpers */

/* Phone app / TelephonyUI artwork, loaded by path at the right scale. */
static UIImage *SPArt(NSString *name)
{
    static NSMutableDictionary *cache;
    if (!cache)
        cache = [NSMutableDictionary new];
    UIImage *hit = cache[name];
    if (hit)
        return hit;
    NSArray *dirs = @[ @"/Applications/MobilePhone.app",
                       @"/System/Library/PrivateFrameworks/TelephonyUI.framework" ];
    NSArray *suffixes = @[ @"@2x~iphone.png", @"@2x.png", @"~iphone.png", @".png" ];
    for (NSString *dir in dirs)
        for (NSString *suf in suffixes) {
            NSString *path = [NSString stringWithFormat:@"%@/%@%@", dir, name, suf];
            UIImage *raw = [UIImage imageWithContentsOfFile:path];
            if (!raw)
                continue;
            CGFloat scale = [suf hasPrefix:@"@2x"] ? 2.0 : 1.0;
            UIImage *img = [UIImage imageWithCGImage:raw.CGImage scale:scale
                                         orientation:UIImageOrientationUp];
            cache[name] = img;
            return img;
        }
    NSLog(@"[SIPPhone] missing artwork %@", name);
    return nil;
}

static NSString *SPDigits(NSString *s)
{
    return [[s componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
}

/* (312) 555-1234 / 1 (312) 555-1234, everything else as dialed */
static NSString *SPPretty(NSString *number)
{
    NSString *d = SPDigits(number);
    if (d.length == 10)
        return [NSString stringWithFormat:@"(%@) %@-%@", [d substringToIndex:3],
                [d substringWithRange:NSMakeRange(3, 3)], [d substringFromIndex:6]];
    if (d.length == 11 && [d hasPrefix:@"1"])
        return [NSString stringWithFormat:@"1 (%@) %@-%@", [d substringWithRange:NSMakeRange(1, 3)],
                [d substringWithRange:NSMakeRange(4, 3)], [d substringFromIndex:7]];
    return number.length ? number : @"Unknown";
}

/* ------------------------------------------------------------------- the UI */

/* six-button panel geometry from the Phone app's sixsqbutton_1..6 artwork */
static const CGFloat kColW[3] = { 96, 91, 97 };
static const CGFloat kRowH[2] = { 107, 115 };
#define kPanelW 284
#define kPanelH 222
enum { kBtnMute = 0, kBtnKeypad, kBtnSpeaker, kBtnAddCall, kBtnHold, kBtnContacts };

@interface SPCallUI : NSObject
+ (SPCallUI *)shared;
- (void)onStateChanged;
- (void)onIncoming;
- (void)syncAtLaunch;
- (void)lockStateChanged;
- (BOOL)homePressed;
- (BOOL)lockPressed;
- (BOOL)silenceRing;
@end

@implementation SPCallUI {
    UIWindow *_win;
    UIImageView *_photo;
    TPLCDView *_lcd;
    UIView *_panel;
    UIButton *_cells[6];
    TPPhonePad *_pad;
    TPBottomSingleButtonBar *_endBar;
    TPBottomDoubleButtonBar *_answerBar;
    TPBottomLockBar *_lockBar;
    UIView *_keypadBar;
    UIWindow *_returnBar;
    UILabel *_returnLabel;
    NSTimer *_tick;
    NSTimer *_vibrate;
    id _ring;                    /* SBUISound, or an AVAudioPlayer fallback */
    NSString *_savedCategory;    /* only used by the AVAudioPlayer fallback */
    int _shownState, _shownCallId;
    BOOL _mute, _speaker, _hold, _keypadUp, _dismissed;
    BOOL _awakeHeld, _silenced;
    NSString *_name, *_label, *_dtmf;
}

+ (SPCallUI *)shared
{
    static SPCallUI *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [SPCallUI new]; });
    return s;
}

- (id)away
{
    Class c = %c(SBAwayController);
    return [c respondsToSelector:@selector(sharedAwayController)] ? [c sharedAwayController] : nil;
}

- (BOOL)isLocked
{
    id away = [self away];
    return [away respondsToSelector:@selector(isLocked)] && [away isLocked];
}

/* ---- construction ---- */

- (UIButton *)cellAt:(int)i icon:(NSString *)icon title:(NSString *)title
{
    int row = i / 3, col = i % 3;
    CGFloat x = 0;
    for (int k = 0; k < col; k++)
        x += kColW[k];
    CGFloat w = kColW[col], h = kRowH[row], y = row ? kRowH[0] : 0;
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.frame = CGRectMake(x, y, w, h);
    NSString *bg = [NSString stringWithFormat:@"sixsqbutton_%d", i + 1];
    NSString *sel = [NSString stringWithFormat:@"sixsqbuttonsel_%d", i + 1];
    [b setBackgroundImage:SPArt(bg) forState:UIControlStateNormal];
    [b setBackgroundImage:SPArt(sel) forState:UIControlStateHighlighted];
    [b setBackgroundImage:SPArt(sel) forState:UIControlStateSelected];
    [b setBackgroundImage:SPArt(sel) forState:UIControlStateSelected | UIControlStateHighlighted];
    UIImageView *iv = [[UIImageView alloc] initWithImage:SPArt(icon)];
    iv.center = CGPointMake(w / 2, h / 2 - 10);
    iv.tag = 10;
    iv.userInteractionEnabled = NO;
    [b addSubview:iv];
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(0, h - 36, w, 18)];
    l.text = title;
    l.textAlignment = NSTextAlignmentCenter;
    l.backgroundColor = [UIColor clearColor];
    l.textColor = [UIColor whiteColor];
    l.font = [UIFont boldSystemFontOfSize:12];
    l.shadowColor = [UIColor colorWithWhite:0 alpha:0.6];
    l.shadowOffset = CGSizeMake(0, -1);
    l.tag = 11;
    l.userInteractionEnabled = NO;
    [b addSubview:l];
    b.tag = i;
    [b addTarget:self action:@selector(tapCell:) forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (UIButton *)barButton:(NSString *)title art:(NSString *)art frame:(CGRect)f action:(SEL)action
{
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.frame = f;
    UIImage *n = [SPArt(art) stretchableImageWithLeftCapWidth:14 topCapHeight:0];
    UIImage *p = [SPArt([art stringByAppendingString:@"_pressed"]) stretchableImageWithLeftCapWidth:14
                                                                                       topCapHeight:0];
    [b setBackgroundImage:n forState:UIControlStateNormal];
    if (p)
        [b setBackgroundImage:p forState:UIControlStateHighlighted];
    [b setTitle:title forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    b.titleLabel.shadowOffset = CGSizeMake(0, -1);
    [b setTitleShadowColor:[UIColor colorWithWhite:0 alpha:0.5] forState:UIControlStateNormal];
    [b addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)build
{
    if (_win)
        return;
    CGRect screen = [UIScreen mainScreen].bounds;
    CGFloat W = screen.size.width, H = screen.size.height;
    _win = [[UIWindow alloc] initWithFrame:screen];
    _win.backgroundColor = [UIColor blackColor];
    _win.hidden = YES;
    /* A plain root view, no view controller: on iOS 6 a root VC's view is sized
       to applicationFrame (y=20, 548 tall), which shifted this absolute layout
       down 20 pt and pushed the bottom bars off screen. */
    UIView *root = [[UIView alloc] initWithFrame:_win.bounds];
    root.backgroundColor = [UIColor blackColor];
    [_win addSubview:root];

    /* The stock call screen sits on the lock-screen wallpaper (a contact photo
       covers it when there is one). SpringBoard's own view keeps it current. */
    Class wallClass = %c(SBWallpaperView);
    if (wallClass) {
        UIView *wall = [[wallClass alloc] initWithOrientation:UIInterfaceOrientationPortrait variant:0];
        if (wall) {
            wall.frame = root.bounds;
            wall.userInteractionEnabled = NO;
            [root addSubview:wall];
        }
        NSLog(@"[SIPPhone] call screen wallpaper view: %@", wall);
    }

    _photo = [[UIImageView alloc] initWithFrame:root.bounds];
    _photo.contentMode = UIViewContentModeScaleAspectFill;
    _photo.clipsToBounds = YES;
    [root addSubview:_photo];

    _lcd = [[%c(TPLCDView) alloc] initWithDefaultSizeForOrientation:UIInterfaceOrientationPortrait];
    CGRect lf = _lcd.frame;
    lf.origin = CGPointMake(0, 20);
    lf.size.width = W;
    _lcd.frame = lf;
    [_lcd setLayoutAsLabelled:YES];
    [root addSubview:_lcd];

    CGFloat barH = [%c(TPBottomBar) defaultHeight];
    if (barH <= 0)
        barH = 96;
    CGRect barFrame = CGRectMake(0, H - barH, W, barH);
    CGFloat top = CGRectGetMaxY(lf), avail = H - barH - top;

    _panel = [[UIView alloc] initWithFrame:CGRectMake((W - kPanelW) / 2, top + (avail - kPanelH) / 2,
                                                      kPanelW, kPanelH)];
    NSArray *icons = @[ @"mute", @"dialer", @"speaker", @"addcall", @"hold", @"contacts" ];
    NSArray *titles = @[ @"mute", @"keypad", @"speaker", @"add call", @"hold", @"contacts" ];
    for (int i = 0; i < 6; i++) {
        _cells[i] = [self cellAt:i icon:icons[i] title:titles[i]];
        [_panel addSubview:_cells[i]];
    }
    for (int i = kBtnAddCall; i <= kBtnContacts; i += 2) {   /* add call, contacts: not in v1 */
        _cells[i].enabled = NO;
        [_cells[i] viewWithTag:10].alpha = 0.35;
        [_cells[i] viewWithTag:11].alpha = 0.35;
    }
    [root addSubview:_panel];

    _pad = [[%c(TPPhonePad) alloc] initWithFrame:CGRectMake((W - kPanelW) / 2, top + (avail - 238) / 2,
                                                            kPanelW, 238)];
    [_pad setDelegate:self];
    [_pad setPlaysSounds:YES];
    _pad.hidden = YES;
    [root addSubview:_pad];

    _endBar = [[%c(TPBottomSingleButtonBar) alloc] initForEndCallWithFrame:barFrame];
    [[_endBar button] addTarget:self action:@selector(tapHangup)
               forControlEvents:UIControlEventTouchUpInside];
    [root addSubview:_endBar];

    _answerBar = [[%c(TPBottomDoubleButtonBar) alloc] initForIncomingCallWithFrame:barFrame];
    [[_answerBar button] addTarget:self action:@selector(tapDecline)
                  forControlEvents:UIControlEventTouchUpInside];
    [[_answerBar button2] addTarget:self action:@selector(tapAnswer)
                   forControlEvents:UIControlEventTouchUpInside];
    NSLog(@"[SIPPhone] answer bar buttons: '%@' / '%@'", [[_answerBar button] currentTitle],
          [[_answerBar button2] currentTitle]);
    [root addSubview:_answerBar];

    _lockBar = [[%c(TPBottomLockBar) alloc] initForIncomingCallWithFrame:barFrame];
    [_lockBar setDelegate:self];
    [_lockBar setLabel:@"slide to answer"];
    [root addSubview:_lockBar];

    /* End Call + Hide Keypad while the keypad is up (TelephonyUI artwork) */
    _keypadBar = [[UIView alloc] initWithFrame:barFrame];
    UIImageView *kbg = [[UIImageView alloc] initWithFrame:_keypadBar.bounds];
    kbg.image = [SPArt(@"bottombarbkgnd") stretchableImageWithLeftCapWidth:39 topCapHeight:0];
    [_keypadBar addSubview:kbg];
    CGFloat bw = (W - 27) / 2, by = (barH - 47) / 2;
    [_keypadBar addSubview:[self barButton:@"End" art:@"bottombarred"
                                     frame:CGRectMake(9, by, bw, 47) action:@selector(tapHangup)]];
    [_keypadBar addSubview:[self barButton:@"Hide Keypad" art:@"bottombargray"
                                     frame:CGRectMake(18 + bw, by, bw, 47)
                                    action:@selector(hideKeypad)]];
    [root addSubview:_keypadBar];

    /* green "Touch to return to call" strip shown when Home hides the screen */
    _returnBar = [[UIWindow alloc] initWithFrame:CGRectMake(0, 0, W, 20)];
    _returnBar.windowLevel = UIWindowLevelStatusBar + 1;
    _returnBar.backgroundColor = [UIColor colorWithRed:0.30 green:0.76 blue:0.28 alpha:1];
    _returnBar.hidden = YES;
    _returnLabel = [[UILabel alloc] initWithFrame:_returnBar.bounds];
    _returnLabel.backgroundColor = [UIColor clearColor];
    _returnLabel.textColor = [UIColor whiteColor];
    _returnLabel.font = [UIFont boldSystemFontOfSize:12];
    _returnLabel.textAlignment = NSTextAlignmentCenter;
    [_returnBar addSubview:_returnLabel];
    [_returnBar addGestureRecognizer:[[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(returnToCall)]];
}

/* ---- contact lookup (name, label, photo) ---- */

- (void)lookUpContact:(NSString *)number
{
    _name = nil;
    _label = nil;
    _photo.image = nil;
    NSString *want = SPDigits(number);
    if (want.length < 7)
        return;
    if (want.length > 10)
        want = [want substringFromIndex:want.length - 10];
    ABAddressBookRef ab = ABAddressBookCreateWithOptions(NULL, NULL);
    if (!ab)
        return;
    CFArrayRef people = ABAddressBookCopyArrayOfAllPeople(ab);
    CFIndex n = people ? CFArrayGetCount(people) : 0;
    for (CFIndex i = 0; i < n && !_name; i++) {
        ABRecordRef p = CFArrayGetValueAtIndex(people, i);
        ABMultiValueRef phones = ABRecordCopyValue(p, kABPersonPhoneProperty);
        if (!phones)
            continue;
        for (CFIndex j = 0; j < ABMultiValueGetCount(phones); j++) {
            NSString *v = (__bridge_transfer NSString *)ABMultiValueCopyValueAtIndex(phones, j);
            NSString *d = SPDigits(v);
            if (d.length > 10)
                d = [d substringFromIndex:d.length - 10];
            if (![d isEqualToString:want])
                continue;
            _name = (__bridge_transfer NSString *)ABRecordCopyCompositeName(p);
            CFStringRef raw = ABMultiValueCopyLabelAtIndex(phones, j);
            if (raw) {
                _label = (__bridge_transfer NSString *)ABAddressBookCopyLocalizedLabel(raw);
                CFRelease(raw);
            }
            if (ABPersonHasImageData(p)) {
                NSData *img = (__bridge_transfer NSData *)ABPersonCopyImageDataWithFormat(
                    p, kABPersonImageFormatOriginalSize);
                _photo.image = [UIImage imageWithData:img];
            }
            break;
        }
        CFRelease(phones);
    }
    if (people)
        CFRelease(people);
    CFRelease(ab);
}

/* ---- screen wake + idle ---- */

/* keep the screen from dimming / auto-locking while a call is on screen */
- (void)holdAwake:(BOOL)on
{
    if (on == _awakeHeld)
        return;
    _awakeHeld = on;
    SpringBoard *sb = (SpringBoard *)[UIApplication sharedApplication];
    if ([sb respondsToSelector:@selector(setIdleTimerDisabled:forReason:)])
        [sb setIdleTimerDisabled:on forReason:@"SIPPhoneCall"];
    id away = [self away];
    if (on && [away respondsToSelector:@selector(cancelDimTimer)])
        [away cancelDimTimer];
    else if (!on && [self isLocked] && [away respondsToSelector:@selector(restartDimTimer)])
        [away restartDimTimer];
}

static float SPBacklightLevel(void)
{
    @try {
        id v = [[UIApplication sharedApplication] valueForKey:@"_currentBacklightLevel"];
        return v ? [v floatValue] : -1;
    } @catch (id e) {
        return -1;
    }
}

/* light the screen for an incoming call, even when the phone is asleep.
   SBAwayController -undimScreen only brings a dimmed lock screen back; once the
   backlight has gone fully off (the phone asleep) it stays dark, which is what
   1.0.10 did. SpringBoard -undim is the call that turns the backlight on. */
- (void)wakeScreen
{
    id away = [self away];
    SpringBoard *sb = (SpringBoard *)[UIApplication sharedApplication];
    float before = SPBacklightLevel();
    if ([sb respondsToSelector:@selector(cancelSetBacklightFactorToZeroAfterDelay)])
        [sb cancelSetBacklightFactorToZeroAfterDelay];
    if ([self isLocked]) {
        if ([sb respondsToSelector:@selector(undim)])
            [sb undim];
        if ([away respondsToSelector:@selector(undimScreen)])
            [away undimScreen];
        if ([away respondsToSelector:@selector(cancelDimTimer)])
            [away cancelDimTimer];       /* undimScreen restarts the ~8 s lock-screen dim timer */
    } else if ([sb respondsToSelector:@selector(resetIdleTimerAndUndim:)]) {
        [sb resetIdleTimerAndUndim:YES];
    }
    NSLog(@"[SIPPhone] wake: backlight %.2f -> %.2f (locked %d)", before, SPBacklightLevel(), [self isLocked]);
    [self performSelector:@selector(ensureScreenOn) withObject:nil afterDelay:0.4];
}

/* last resort if the screen is still dark while it rings */
- (void)ensureScreenOn
{
    if (_win.hidden || !_lockBar || (_lockBar.hidden && _answerBar.hidden))
        return;                          /* no longer ringing */
    float level = SPBacklightLevel();
    if (level == 0) {
        SpringBoard *sb = (SpringBoard *)[UIApplication sharedApplication];
        if ([sb respondsToSelector:@selector(setBacklightFactor:)])
            [sb setBacklightFactor:1.0f];
        NSLog(@"[SIPPhone] wake: backlight still off, forced on (now %.2f)", SPBacklightLevel());
    }
}

/* ---- showing / hiding ---- */

- (void)applyWindowLevel
{
    /* above the lock screen (1050) when locked; just under the status bar
       otherwise so the clock/battery stay visible like the stock call screen */
    _win.windowLevel = [self isLocked] ? UIWindowLevelAlert + 100 : UIWindowLevelStatusBar - 1;
}

- (void)show
{
    [self build];
    [self applyWindowLevel];
    _returnBar.hidden = YES;
    if (_win.hidden) {
        _win.hidden = NO;            /* no makeKeyAndVisible: never steal SpringBoard's key window */
        static BOOL logged;
        if (!logged) {
            logged = YES;
            UIView *root = _win.subviews.count ? [_win.subviews objectAtIndex:0] : nil;
            NSLog(@"[SIPPhone] call window root %@", NSStringFromCGRect(root.frame));
            for (UIWindow *w in [UIApplication sharedApplication].windows)
                NSLog(@"[SIPPhone] window %@ level %.1f hidden %d", NSStringFromClass([w class]),
                      w.windowLevel, w.hidden);
        }
    }
}

- (void)hide
{
    _win.hidden = YES;
    _returnBar.hidden = YES;
    [self stopRing];
    [_tick invalidate];
    _tick = nil;
    [UIDevice currentDevice].proximityMonitoringEnabled = NO;
    [self setKeypadVisible:NO];
    [_lockBar stopAnimating];
    [_lockBar relock];
    [self holdAwake:NO];
    _dismissed = NO;
    _silenced = NO;
}

- (BOOL)homePressed
{
    /* Home during a call: behave like the stock phone, drop to the springboard
       and leave a green "touch to return" strip. Never swallow the press, and
       never hide the call under the lock screen (the strip can't show there). */
    if (!_win || _win.hidden || [self isLocked])
        return NO;
    SPClient *c = [SPClient shared];
    if (c.callState == SPUI_ACTIVE || c.callState == SPUI_CALLING || c.callState == SPUI_RINGING) {
        _dismissed = YES;
        _win.hidden = YES;
        [UIDevice currentDevice].proximityMonitoringEnabled = NO;
        [self holdAwake:NO];
        _returnBar.hidden = NO;
        [self updateTimer];
    }
    return NO;
}

/* Sleep button while ringing: 1st press silences, 2nd declines (stock). With
   the screen already dark, just silence and let SpringBoard wake it. */
- (BOOL)lockPressed
{
    if (!_win || _win.hidden || [SPClient shared].callState != SPUI_INCOMING)
        return NO;
    id away = [self away];
    if ([away respondsToSelector:@selector(isDimmed)] && [away isDimmed]) {
        [self stopRing];
        _silenced = YES;
        return NO;
    }
    if (!_silenced) {
        [self stopRing];
        _silenced = YES;
        return YES;
    }
    [self tapDecline];
    return YES;
}

/* Volume button while ringing silences the ring (stock) */
- (BOOL)silenceRing
{
    if (!_ring && !_vibrate)
        return NO;
    [self stopRing];
    _silenced = YES;
    return YES;
}

- (void)lockStateChanged
{
    if (!_win)
        return;
    SPClient *c = [SPClient shared];
    [c refresh];
    if (c.callState == SPUI_IDLE || c.callState == SPUI_ENDED)
        return;
    if ([self isLocked])
        _dismissed = NO;             /* the green strip can't show on the lock screen */
    [self onStateChanged];           /* re-levels via show, re-picks answer bar vs slide bar */
}

- (void)returnToCall
{
    _dismissed = NO;
    [self show];
    [self onStateChanged];
}

- (void)setKeypadVisible:(BOOL)up
{
    _keypadUp = up;
    _pad.hidden = !up;
    _panel.hidden = up;
    _keypadBar.hidden = !up;
    _endBar.hidden = up;
    _dtmf = up ? @"" : nil;
    [self updateLCD];
}

/* ---- ringtone + vibrate ---- */

- (NSString *)ringtoneIdentifier
{
    Class sp = %c(SBSoundPreferences);
    NSString *ident = [sp respondsToSelector:@selector(ringtoneIdentifier)] ? [sp ringtoneIdentifier] : nil;
    if (!ident) {
        @try {
            ident = [[%c(TLToneManager) sharedRingtoneManager] currentRingtoneIdentifier];
        } @catch (id e) {}
    }
    return ident;
}

- (void)startRing
{
    if (_ring || _vibrate)
        return;
    BOOL muted = NO, vibrate = YES;
    Class mc = %c(SBMediaController), sp = %c(SBSoundPreferences);
    id media = [mc respondsToSelector:@selector(sharedInstance)] ? [mc sharedInstance] : nil;
    if ([media respondsToSelector:@selector(isRingerMuted)])
        muted = [media isRingerMuted];
    if ([sp respondsToSelector:@selector(shouldVibrateForCurrentRingerState)])
        vibrate = [sp shouldVibrateForCurrentRingerState];
    NSString *how = @"none";
    if (!muted) {
        NSString *ident = [self ringtoneIdentifier];
        Class soundClass = %c(SBUISound);
        if (ident && soundClass) {
            SBUISound *snd = [[soundClass alloc] initWithRingtone:ident vibrationPattern:nil
                                                          repeats:YES audioCategory:@"Ringtone"];
            if ([snd play]) {
                _ring = snd;
                how = @"SBUISound";
            }
        }
        if (!_ring) {
            /* fallback: AVAudioPlayer (media volume) */
            NSString *path = [sp respondsToSelector:@selector(ringtonePath)] ? [sp ringtonePath] : nil;
            if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
                path = nil;
                @try {
                    TLToneManager *tm = [%c(TLToneManager) sharedRingtoneManager];
                    id ti = [tm currentRingtoneIdentifier];
                    if (ti)
                        path = [tm copyPathOfRingtoneWithIdentifier:ti];
                    if (!path)
                        path = [tm defaultRingtonePath];
                } @catch (id e) {}
            }
            if (path) {
                AVAudioSession *s = [AVAudioSession sharedInstance];
                _savedCategory = s.category;
                [s setCategory:AVAudioSessionCategoryPlayback error:nil];
                [s setActive:YES error:nil];
                AVAudioPlayer *pl = [[AVAudioPlayer alloc] initWithContentsOfURL:[NSURL fileURLWithPath:path]
                                                                           error:nil];
                pl.numberOfLoops = -1;
                [pl play];
                _ring = pl;
                how = @"AVAudioPlayer";
            }
        }
    }
    NSLog(@"[SIPPhone] ringing: muted=%d vibrate=%d via %@", muted, vibrate, how);
    if (vibrate) {
        [self vibrateOnce];
        _vibrate = [NSTimer scheduledTimerWithTimeInterval:1.6 target:self
                    selector:@selector(vibrateOnce) userInfo:nil repeats:YES];
    }
}

- (void)vibrateOnce
{
    AudioServicesPlayAlertSound(kSystemSoundID_Vibrate);
}

- (void)stopRing
{
    [_vibrate invalidate];
    _vibrate = nil;
    if (!_ring)
        return;
    [_ring stop];
    if ([_ring isKindOfClass:[AVAudioPlayer class]]) {
        AVAudioSession *s = [AVAudioSession sharedInstance];
        [s setActive:NO withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation error:nil];
        if (_savedCategory)
            [s setCategory:_savedCategory error:nil];
        _savedCategory = nil;
    }
    _ring = nil;
}

/* ---- state ---- */

- (NSString *)title
{
    if (_keypadUp && _dtmf.length)
        return _dtmf;
    if (_name.length)
        return _name;
    SPClient *c = [SPClient shared];
    if (c.callDisplay.length && ![c.callDisplay isEqualToString:c.callNumber])
        return c.callDisplay;
    return SPPretty(c.callNumber);
}

- (void)updateLCD
{
    if (!_lcd)
        return;
    SPClient *c = [SPClient shared];
    [_lcd setText:[self title]];
    NSString *label;
    switch (c.callState) {
    case SPUI_INCOMING: label = _label.length ? _label : @"SIP call"; break;
    case SPUI_CALLING: label = @"calling…"; break;
    case SPUI_RINGING: label = @"ringing…"; break;
    case SPUI_ACTIVE: label = c.held ? @"on hold" : [self elapsed]; break;
    case SPUI_ENDED: label = c.callReason.length && ![c.callReason isEqualToString:@"Call ended"]
                                 ? c.callReason : @"call ended";
        break;
    default: label = @""; break;
    }
    [_lcd setLabel:label];
}

- (NSString *)elapsed
{
    long start = [SPClient shared].callStart;
    if (start <= 0)
        return @"00:00";
    long d = (long)time(NULL) - start;
    if (d < 0)
        d = 0;
    if (d >= 3600)
        return [NSString stringWithFormat:@"%ld:%02ld:%02ld", d / 3600, (d / 60) % 60, d % 60];
    return [NSString stringWithFormat:@"%02ld:%02ld", d / 60, d % 60];
}

- (void)updateTimer
{
    [self updateLCD];
    if (!_returnBar.hidden)
        _returnLabel.text = [NSString stringWithFormat:@"Touch to return to call  %@", [self elapsed]];
}

- (void)syncButtons
{
    _cells[kBtnMute].selected = _mute;
    _cells[kBtnSpeaker].selected = _speaker;
    _cells[kBtnHold].selected = _hold;
}

- (void)onIncoming
{
    [self onStateChanged];
}

/* At SpringBoard (re)launch: a call that ended before the respring is adopted
   silently instead of flashing its "call ended" screen. */
- (void)syncAtLaunch
{
    SPClient *c = [SPClient shared];
    [c refresh];
    if (c.callState == SPUI_ENDED) {
        _shownCallId = c.callId;
        _shownState = SPUI_ENDED;
        return;
    }
    [self onStateChanged];
}

- (void)onStateChanged
{
    SPClient *c = [SPClient shared];
    [c refresh];
    int s = c.callState;
    _mute = c.muted;
    _speaker = c.speaker;
    _hold = c.held;

    if (s == SPUI_IDLE) {
        [self hide];
        _shownState = s;
        _shownCallId = 0;                 /* ids may repeat after a daemon restart */
        return;
    }
    if (s == SPUI_ENDED) {
        /* show "call ended" once per call: later publishes (registration
           changes, mute resets) must not pop the screen back up */
        if (c.callId == _shownCallId && _shownState == SPUI_ENDED)
            return;
        if (c.callIncoming && c.callStart <= 0) {
            /* declined or missed: the stock phone just dismisses */
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(hideIfEnded) object:nil];
            [self hide];
            _shownCallId = c.callId;
            _shownState = s;
            return;
        }
    }
    [self build];
    if (c.callId != _shownCallId) {          /* new call: fresh screen */
        _shownCallId = c.callId;
        _dismissed = NO;
        _silenced = NO;
        [self setKeypadVisible:NO];
        [self lookUpContact:c.callNumber];
    }
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(hideIfEnded) object:nil];

    BOOL incoming = s == SPUI_INCOMING;
    BOOL locked = [self isLocked];
    if (s != SPUI_ENDED && !_dismissed)
        [self holdAwake:YES];
    if (incoming && _shownState != SPUI_INCOMING)
        [self wakeScreen];

    _answerBar.hidden = !(incoming && !locked);
    _lockBar.hidden = !(incoming && locked);
    if (incoming && locked) {
        if (![_lockBar isAnimating])
            [_lockBar startAnimating];
    } else {
        [_lockBar stopAnimating];
    }
    _panel.hidden = incoming || _keypadUp;
    _pad.hidden = incoming || !_keypadUp;
    _endBar.hidden = incoming || _keypadUp;
    _keypadBar.hidden = incoming || !_keypadUp;

    if (incoming) {
        if (_shownState != SPUI_INCOMING && !_silenced)
            [self startRing];
    } else {
        [self stopRing];
    }

    if (s == SPUI_ACTIVE || s == SPUI_CALLING || s == SPUI_RINGING) {
        if (!_tick)
            _tick = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self
                     selector:@selector(updateTimer) userInfo:nil repeats:YES];
    } else {
        [_tick invalidate];
        _tick = nil;
    }

    /* the ended screen is inert: taps must not reach the daemon */
    BOOL ended = s == SPUI_ENDED;
    _endBar.userInteractionEnabled = !ended;
    _panel.userInteractionEnabled = !ended;
    _pad.userInteractionEnabled = !ended;
    _keypadBar.userInteractionEnabled = !ended;
    if (ended)
        [self performSelector:@selector(hideIfEnded) withObject:nil afterDelay:1.5];

    /* earpiece calls blank the screen against your face; not on speaker */
    BOOL inCall = s == SPUI_ACTIVE || s == SPUI_CALLING || s == SPUI_RINGING;
    [UIDevice currentDevice].proximityMonitoringEnabled = inCall && !_speaker && !_dismissed;

    [self updateLCD];
    [self syncButtons];
    if (_dismissed && ended) {
        [self hide];                        /* ended while backgrounded: just drop the strip */
    } else if (_dismissed && !incoming) {
        _returnBar.hidden = NO;             /* still backgrounded behind the green strip */
        [self updateTimer];
    } else {
        [self show];
    }
    _shownState = s;
}

- (void)hideIfEnded
{
    SPClient *c = [SPClient shared];
    [c refresh];
    if (c.callState == SPUI_ENDED || c.callState == SPUI_IDLE)
        [self hide];
}

/* ---- actions ---- */

- (void)tapAnswer
{
    [self stopRing];
    [_lockBar stopAnimating];
    [[SPClient shared] answer];
}

- (void)tapDecline
{
    [self stopRing];
    [[SPClient shared] hangup];
}

- (void)tapHangup
{
    [[SPClient shared] hangup];
}

- (void)tapCell:(UIButton *)b
{
    switch (b.tag) {
    case kBtnMute:
        _mute = !_mute;
        [[SPClient shared] setMute:_mute];
        break;
    case kBtnSpeaker:
        _speaker = !_speaker;
        [[SPClient shared] setSpeaker:_speaker];
        [UIDevice currentDevice].proximityMonitoringEnabled = !_speaker;
        break;
    case kBtnHold:
        _hold = !_hold;
        [[SPClient shared] setHold:_hold];
        break;
    case kBtnKeypad:
        [self setKeypadVisible:YES];
        break;
    default:
        break;
    }
    [self syncButtons];
}

- (void)hideKeypad
{
    [self setKeypadVisible:NO];
}

/* TPPhonePad delegate (selectors from TelephonyUI on 6.1.2) */
- (void)phonePad:(id)pad appendString:(NSString *)s
{
    if (!s.length)
        return;
    [[SPClient shared] sendDTMF:s];
    _dtmf = [(_dtmf ?: @"") stringByAppendingString:s];
    [self updateLCD];
}
- (void)phonePad:(id)pad keyDown:(char)key {}
- (void)phonePad:(id)pad keyUp:(char)key {}
- (void)phonePadDeleteLastDigit:(id)pad {}

/* TPBottomLockBar delegate: slide to answer */
- (void)lockBarUnlocked:(id)bar
{
    [bar stopAnimating];              /* TPLockKnobView's upInKnob restarts the shimmer timer */
    [self tapAnswer];
}
- (void)lockBarStartedTracking:(id)bar {}
- (void)lockBarStoppedTracking:(id)bar {}
- (void)lockBarSlidBackToOrigin:(id)bar {}

@end

/* ------------------------------------------------------------- notify wiring */

static void stateCb(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj,
                    CFDictionaryRef ui)
{
    dispatch_async(dispatch_get_main_queue(), ^{ [[SPCallUI shared] onStateChanged]; });
}

static void incomingCb(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj,
                       CFDictionaryRef ui)
{
    dispatch_async(dispatch_get_main_queue(), ^{ [[SPCallUI shared] onIncoming]; });
}

static BOOL sSwallowLockUp;

%hook SpringBoard

- (void)applicationDidFinishLaunching:(id)app
{
    %orig;
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, stateCb,
        CFSTR(SP_NOTIFY_STATE), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, incomingCb,
        CFSTR(SP_NOTIFY_INCOMING), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    int tok;
    notify_register_dispatch("com.apple.springboard.lockstate", &tok, dispatch_get_main_queue(),
                             ^(int t) { [[SPCallUI shared] lockStateChanged]; });
    /* reflect a call already in progress when SpringBoard (re)launches */
    dispatch_async(dispatch_get_main_queue(), ^{ [[SPCallUI shared] syncAtLaunch]; });
}

- (void)menuButtonUp:(struct __GSEvent *)event
{
    [[SPCallUI shared] homePressed];
    %orig;
}

/* swallow BOTH halves of a press we handle: SpringBoard locks on button-up, and
   a swallowed down alone leaves the hold timer armed (power-off slider) */
- (void)lockButtonDown:(struct __GSEvent *)event
{
    if ([[SPCallUI shared] lockPressed]) {
        sSwallowLockUp = YES;
        return;
    }
    sSwallowLockUp = NO;
    %orig;
}

- (void)lockButtonUp:(struct __GSEvent *)event
{
    if (sSwallowLockUp) {
        sSwallowLockUp = NO;
        return;
    }
    %orig;
}

- (void)volumeChanged:(struct __GSEvent *)event
{
    if ([[SPCallUI shared] silenceRing])
        return;
    %orig;
}

%end

/* SIPPhone — MobilePhone hook.
   Routes the stock dialer (keypad, Contacts, Recents, Favorites all funnel
   through -[PhoneApplication dialPhoneNumber:...]) to the SIP daemon instead
   of CoreTelephony when SIP routing is enabled. The call UI is drawn by the
   SpringBoard hook, so here we just redirect and get out of the way.
   On iOS 6.1.2 all four variants return BOOL (type 'c'): YES = dial handled. */
#import <UIKit/UIKit.h>
#import "SPClient.h"

@interface PhoneApplication : NSObject
- (BOOL)dialPhoneNumber:(id)n forUID:(int)uid dialAssist:(BOOL)da wasAlreadyAssisted:(BOOL)wa;
- (BOOL)dialPhoneNumber:(id)n forUID:(int)uid dialAssist:(BOOL)da;
- (BOOL)dialPhoneNumber:(id)n dialAssist:(BOOL)da;
- (BOOL)dialPhoneNumber:(id)n;
@end

static void alert(NSString *title, NSString *message)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertView *a = [[UIAlertView alloc] initWithTitle:title message:message delegate:nil
                                          cancelButtonTitle:@"OK" otherButtonTitles:nil];
        [a show];
    });
}

static BOOL route(id n)
{
    if (![n isKindOfClass:[NSString class]])
        return NO;
    NSString *number = n;
    SPClient *sp = [SPClient shared];
    if (![sp routingEnabled] || number.length == 0)
        return NO;
    /* Keep real emergency calls on the cellular radio, never SIP. */
    NSString *digits = [[number componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
    for (NSString *e in @[@"911", @"112", @"999", @"000", @"110", @"933"])
        if ([digits isEqualToString:e])
            return NO;
    /* Registration check: say why instead of failing silently. This line has
       no cellular voice, so a refused SIP call is still "handled" (YES). */
    NSString *why = [sp notReadyReason];
    if (why) {
        NSLog(@"[SIPPhone] dial blocked: %@", why);
        alert(@"SIP Not Registered",
              [NSString stringWithFormat:@"%@\n\nCheck Settings > SIP Phone.", why]);
        return YES;
    }
    if (![sp dial:number]) {
        NSLog(@"[SIPPhone] dial: daemon unreachable");
        alert(@"SIP Phone", @"The SIP Phone service didn't answer. Try again in a few seconds.");
        return YES;
    }
    NSLog(@"[SIPPhone] dial routed to SIP (%lu digits)", (unsigned long)digits.length);
    return YES;
}

%hook PhoneApplication

- (BOOL)dialPhoneNumber:(id)n forUID:(int)uid dialAssist:(BOOL)da wasAlreadyAssisted:(BOOL)wa
{
    if (route(n))
        return YES;
    return %orig;
}

- (BOOL)dialPhoneNumber:(id)n forUID:(int)uid dialAssist:(BOOL)da
{
    if (route(n))
        return YES;
    return %orig;
}

- (BOOL)dialPhoneNumber:(id)n dialAssist:(BOOL)da
{
    if (route(n))
        return YES;
    return %orig;
}

- (BOOL)dialPhoneNumber:(id)n
{
    if (route(n))
        return YES;
    return %orig;
}

%end

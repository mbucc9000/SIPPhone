/* SIPPhone Settings pane: Settings > SIP Phone.
   Mirrors the TapticAlerts pane that works on this device: real class chain
   (PSListController : PSViewController : UIViewController), _specifiers set
   directly, XML Root.plist. Edits com.mbucc9000.sipphone and posts
   com.mbucc9000.sipphone.prefs so sipphoned re-reads and re-registers. */
#import <UIKit/UIKit.h>
#import <notify.h>
#import "sp_proto.h"

@interface PSSpecifier : NSObject
- (id)propertyForKey:(NSString *)key;
@end

@interface PSViewController : UIViewController
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier;
@end

@interface PSListController : PSViewController {
    NSArray *_specifiers;
}
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)name target:(id)target;
- (void)reloadSpecifierID:(NSString *)identifier;
- (NSBundle *)bundle;
@end

@interface SIPPhoneListController : PSListController
@end

static void SPStateChanged(CFNotificationCenterRef center, void *observer, CFStringRef name,
                           const void *object, CFDictionaryRef info)
{
    SIPPhoneListController *c = (__bridge SIPPhoneListController *)observer;
    dispatch_async(dispatch_get_main_queue(), ^{
        [c reloadSpecifierID:@"status"];
    });
}

@implementation SIPPhoneListController

- (id)specifiers
{
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
        NSLog(@"[SIPPhone] prefs: bundle %@, %lu rows",
              [[self bundle] bundlePath], (unsigned long)[_specifiers count]);
    }
    return _specifiers;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    (__bridge const void *)self, SPStateChanged,
                                    CFSTR(SP_NOTIFY_STATE), NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
}

- (void)dealloc
{
    CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                       (__bridge const void *)self, CFSTR(SP_NOTIFY_STATE), NULL);
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    if (_specifiers)
        [self reloadSpecifierID:@"status"];
}

- (id)readPreferenceValue:(PSSpecifier *)spec
{
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@SP_PREFS_PATH];
    id v = [d objectForKey:[spec propertyForKey:@"key"]];
    return v ? v : [spec propertyForKey:@"default"];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)spec
{
    NSString *key = [spec propertyForKey:@"key"];
    if (!key)
        return;
    NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:@SP_PREFS_PATH];
    if (!d)
        d = [NSMutableDictionary dictionary];
    if (value)
        [d setObject:value forKey:key];
    else
        [d removeObjectForKey:key];
    [d writeToFile:@SP_PREFS_PATH atomically:YES];
    notify_post(SP_NOTIFY_PREFS);
}

- (id)statusText:(PSSpecifier *)spec
{
    NSDictionary *s = [NSDictionary dictionaryWithContentsOfFile:@SP_STATE_PATH];
    NSString *detail = [s objectForKey:@SP_K_REG_DETAIL];
    return [detail length] ? detail : @"Daemon not running";
}

- (void)reregister:(PSSpecifier *)spec
{
    notify_post(SP_NOTIFY_REREGISTER);
}

@end

<img src="icon.png" width="80" align="right" alt="">

# SIP Phone

Make and receive VoIP.ms calls through the stock iOS 6 Phone app, with a stock-style call screen and your own ringtone. Optional encrypted calls (SIP over TLS + SRTP).

## Features

- Dial from the stock Phone app and the call goes over SIP. 911 and other emergency numbers stay on cellular.
- Incoming calls ring with your ringtone, wake the screen and show a stock-style call screen on your wallpaper. Slide to answer when locked.
- Mute, keypad, speaker and hold during a call.
- Clean earpiece audio: Auto mode turns iOS's choppy echo suppressor off on the earpiece and keeps it for speaker.
- Encrypted calls (optional): SIP over TLS and SRTP, so the login, the numbers you dial and the call itself can't be read on the network.

## How to use

1. On voip.ms, create a sub-account. For incoming calls, get a number (DID) and route it to that sub-account.
2. Settings › SIP Phone: enter the server (like chicago4.voip.ms), the sub-account and its password, then turn on SIP enabled. Status shows Registered.
3. Dial from the Phone app as usual. Call 4443 for VoIP.ms's echo test.
4. To encrypt your calls: go to voip.ms, log in, go to Sub Accounts, then Manage Sub Accounts, and switch Encrypted SIP Traffic to Yes. Then in Settings › SIP Phone › Security, turn on Encrypted calls. Both must be on together.
5. To show your own number on outgoing calls: at voip.ms, edit your sub-account, and by CallerID Number click the link to verify your real number (it sends a code by call or text). Enter the code, then pick that number as the Caller ID. Calls then show your number, not the VoIP.ms one.

## Requirements

- Jailbroken iOS 6 (tested on an iPhone 5 with iOS 6.1.2)
- Cydia Substrate and PreferenceLoader (Cydia installs them for you)
- A VoIP.ms account (a sub-account and a server like chicago4.voip.ms)

## Install

In Cydia, add `https://mbucc9000.github.io/slopkit/` and install **SIP Phone**. Or download the `.deb` from [Releases](../../releases) and install it with `dpkg -i`.

## Building

[Theos](https://theos.dev) with the iOS 6.1 SDK: `make package FINALPACKAGE=1`.

## License

MIT.

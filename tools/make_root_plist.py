"""Generates sipphoneprefs/Resources/Root.plist as an XML plist.
XML (not old-style ASCII) matches the working TapticAlerts pane and gives
switches/segments real <integer>/<true/> types.
    py -3 tools/make_root_plist.py
"""
import os
import plistlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "sipphoneprefs", "Resources", "Root.plist")


def group(label, footer=None):
    d = {"cell": "PSGroupCell", "label": label}
    if footer:
        d["footerText"] = footer
    return d


def text(label, key, default="", keyboard=None, secure=False, placeholder=None):
    d = {
        "cell": "PSSecureEditTextCell" if secure else "PSEditTextCell",
        "label": label,
        "key": key,
        "default": default,
        "autoCaps": "none",             # PSEditTextCell: no auto-capitalisation
        "noAutoCorrect": True,
    }
    if keyboard:
        d["keyboard"] = keyboard
    if placeholder:
        d["placeholder"] = placeholder
    return d


def switch(label, key, default):
    return {"cell": "PSSwitchCell", "label": label, "key": key, "default": default}


items = [
    group("Account", "Your VoIP.ms sub-account. Use a server with a trailing number, "
                     "e.g. chicago4.voip.ms (Main Menu > Sub Accounts on voip.ms)."),
    text("Server", "server", keyboard="URL", placeholder="chicago4.voip.ms"),
    text("Username", "username", placeholder="100000_iphone5"),
    text("Password", "password", secure=True),
    text("Auth user", "authUser", placeholder="optional"),
    text("Display name", "displayName", placeholder="optional"),

    group("Connection"),
    {"cell": "PSSegmentCell", "label": "Transport", "key": "transport", "default": 0,
     "validTitles": ["UDP", "TCP"], "validValues": [0, 1]},
    text("Port", "port", default="5060", keyboard="numbers"),
    text("Register every (s)", "expires", default="300", keyboard="numbers"),

    group("Calls", "When SIP is on, calls you dial in the Phone app go over SIP. "
                   "911 and other emergency numbers always use the cellular radio."),
    switch("SIP enabled", "enabled", False),
    switch("Route Phone app calls", "routeAllCalls", True),

    group("Bluetooth", "Lets AirPods or another Bluetooth headset carry calls. Off by default: "
                       "AirPods Pro 3 on iOS 6 can't hold the call-audio link, and if it stalls "
                       "SIP Phone moves the call back to the iPhone."),
    switch("Use Bluetooth headset (beta)", "btHeadset", False),

    group("Status", "Live registration state from the SIP Phone daemon."),
    {"cell": "PSTitleValueCell", "label": "Status", "id": "status", "get": "statusText:"},
    {"cell": "PSButtonCell", "label": "Re-register now", "action": "reregister:"},

    group("Troubleshooting", "Detailed log writes every SIP message (passwords redacted) to "
                             "/var/mobile/SIPPhone.log and records the audio of echo-test (4443) "
                             "calls only. "
                             "Call audio: Auto turns iOS voice processing off on the earpiece "
                             "(its echo suppressor chops your voice) and keeps it for speaker. "
                             "Processed = always on, Raw = always off. Applies to the next call."),
    switch("Detailed log", "debugLog", False),
    {"cell": "PSSegmentCell", "label": "Call audio", "key": "audioMode", "default": 0,
     "validTitles": ["Auto", "Processed", "Raw"], "validValues": [0, 1, 2]},
]

root = {"title": "SIP Phone", "items": items}

with open(OUT, "wb") as f:
    plistlib.dump(root, f, fmt=plistlib.FMT_XML)
print("wrote", os.path.normpath(OUT), len(items), "items")

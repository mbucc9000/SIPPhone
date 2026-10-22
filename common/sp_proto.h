/* Shared contract between sipphoned (daemon) and the UI tweaks. */
#ifndef SP_PROTO_H
#define SP_PROTO_H

#define SP_SOCK_PATH   "/var/run/sipphone.sock"
#define SP_PREFS_PATH  "/var/mobile/Library/Preferences/com.mbucc9000.sipphone.plist"
#define SP_STATE_PATH  "/var/mobile/Library/Preferences/com.mbucc9000.sipphone.state.plist"
#define SP_LOG_PATH    "/var/mobile/SIPPhone.log"

/* Darwin notifications (no payload; the listener then reads the state plist). */
#define SP_NOTIFY_STATE   "com.mbucc9000.sipphone.state"   /* reg or call state changed */
#define SP_NOTIFY_INCOMING "com.mbucc9000.sipphone.incoming" /* a call is now ringing */
#define SP_NOTIFY_PREFS   "com.mbucc9000.sipphone.prefs"    /* UI changed prefs; reload */
#define SP_NOTIFY_REREGISTER "com.mbucc9000.sipphone.reregister" /* re-register even if nothing changed */

/* Commands the UI sends over the socket (one per line, '\n' terminated). */
/* DIAL <number>            place an outgoing call
 * ANSWER                   answer the ringing call
 * HANGUP                   cancel / decline / end
 * HOLD <0|1>
 * MUTE <0|1>
 * SPEAKER <0|1>
 * DTMF <char>
 * RELOAD                   re-read prefs (also triggered by the Darwin notify)
 * STATUS                   reply with one STATE line
 * PING                     reply PONG
 */

/* Events the daemon streams to connected clients (also mirrored in the state plist):
 * REG <state:int> <detail...>
 * CALL <state:int> <incoming:0|1> <muted> <held> <speaker> <number> | <display>
 * The call line puts number/display last, display after a " | " so spaces are safe.
 */

/* state plist keys (written atomically by the daemon on every change) */
#define SP_K_REG_STATE   "regState"
#define SP_K_REG_DETAIL  "regDetail"
#define SP_K_CALL_STATE  "callState"
#define SP_K_CALL_INCOMING "callIncoming"
#define SP_K_CALL_NUMBER "callNumber"
#define SP_K_CALL_DISPLAY "callDisplay"
#define SP_K_CALL_REASON "callReason"
#define SP_K_CALL_MUTED  "callMuted"
#define SP_K_CALL_HELD   "callHeld"
#define SP_K_CALL_SPEAKER "callSpeaker"
#define SP_K_CALL_START  "callStart"      /* unix seconds, 0 until connected */
#define SP_K_CALL_ID     "callId"

/* prefs plist keys */
#define SP_PK_ENABLED    "enabled"
#define SP_PK_SERVER     "server"
#define SP_PK_PORT       "port"
#define SP_PK_TRANSPORT  "transport"      /* 0 udp, 1 tcp */
#define SP_PK_USER       "username"
#define SP_PK_AUTHUSER   "authUser"
#define SP_PK_PASSWORD   "password"
#define SP_PK_DISPLAY    "displayName"
#define SP_PK_EXPIRES    "expires"
#define SP_PK_ROUTEALL   "routeAllCalls"  /* 1 = stock Phone dials go to SIP */
#define SP_PK_CODEC_PCMA "preferPCMA"     /* 1 = offer A-law first (not used yet) */
#define SP_PK_DEBUG      "debugLog"       /* 1 = full SIP messages in the log (auth redacted) */
#define SP_PK_BTHEADSET  "btHeadset"      /* 1 = let a Bluetooth headset (HFP) carry calls; off by default */
#define SP_PK_AUDIO      "audioMode"      /* 0 auto (VP off on the earpiece), 1 always VP, 2 never VP */

#endif

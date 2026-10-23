/* iOS 6 call audio: a VoiceProcessingIO AudioUnit at 8 kHz mono, wired to sp_rtp.
   The input callback encodes 20 ms of mic PCM into an RTP packet and sends it;
   the output callback pulls 20 ms of playout PCM from the jitter buffer.
   All sp_rtp access is under one lock shared with the RTP receive path. */
#ifndef SP_AUDIO_H
#define SP_AUDIO_H

#include "sp_rtp.h"

typedef struct sp_audio sp_audio;

/* Sends a built RTP packet to the peer. Called from the realtime audio thread. */
typedef void (*sp_audio_tx)(void *ctx, const uint8_t *pkt, int len);

sp_audio *sp_audio_new(sp_audio_tx tx, void *ctx);
void      sp_audio_free(sp_audio *a);

enum { SP_AU_TONE_NONE = 0, SP_AU_TONE_RINGBACK, SP_AU_TONE_BUSY };

/* Enable SRTP for the call (30-byte SDES keys), or pass NULL,NULL to send plain RTP.
   Set before sp_audio_start / sp_audio_reconfigure. */
void sp_audio_set_srtp(sp_audio *a, const uint8_t *tx_key, const uint8_t *rx_key);

/* Start/stop the call audio. codec_pt is SP_PT_PCMU/PCMA, dtmf_pt or -1. */
int  sp_audio_start(sp_audio *a, int codec_pt, int dtmf_pt, int sending, int recving);
/* Re-key the RTP stream once the real codec is negotiated (keeps the unit up). */
void sp_audio_reconfigure(sp_audio *a, int codec_pt, int dtmf_pt, int sending, int recving);
void sp_audio_update_dir(sp_audio *a, int sending, int recving);
/* Local comfort tone played to the user while media is not yet flowing. */
void sp_audio_set_tone(sp_audio *a, int tone);
void sp_audio_stop(sp_audio *a);

void sp_audio_set_mute(sp_audio *a, int muted);     /* mic */
int  sp_audio_set_speaker(sp_audio *a, int on);     /* speaker vs earpiece route */
void sp_audio_send_dtmf(sp_audio *a, char digit);

/* Feed an inbound RTP packet (called from the main loop). */
void sp_audio_rtp_in(sp_audio *a, const uint8_t *pkt, int len);

/* Copy current RTP stats (thread-safe snapshot). */
void sp_audio_stats(sp_audio *a, uint32_t *tx, uint32_t *rx, uint32_t *lost);

int  sp_audio_is_running(sp_audio *a);        /* unit up (or paused by an interruption) */
/* Settings > Call audio, applied at the next sp_audio_start.
   AUTO: iOS voice processing off on the built-in earpiece (its echo suppressor
   chops your voice whenever the far end talks too), on for speaker/headsets. */
enum { SP_AU_MODE_AUTO = 0, SP_AU_MODE_PROCESSED, SP_AU_MODE_RAW };
void sp_audio_set_mode(sp_audio *a, int mode);
/* Allow a Bluetooth headset to carry the call (next start). Off by default: AirPods Pro 3
   on iOS 6 fail to bring up the HFP/SCO link and stall all call audio. */
void sp_audio_set_bluetooth(sp_audio *a, int on);
/* Call from the main loop every iteration while audio is up (route-driven rebuilds). */
void sp_audio_service(sp_audio *a);
/* Record both directions of the next call to /var/mobile/SIPPhone-{mic,spk}.wav.
   Debugging aid for the VoIP.ms echo test only: main.c never enables it for a call
   with another person (recording them without consent is not OK, and illegal in
   all-party-consent states). */
void sp_audio_set_capture(sp_audio *a, int on);
void sp_audio_delete_captures(void);
/* one-line debug snapshot (callbacks, mic level, render errors, RTP counters); resets the peak */
void sp_audio_debug(sp_audio *a, char *out, size_t n);
void sp_audio_watchdog(sp_audio *a);          /* call about once a second while audio is up */
int  sp_audio_take_route_change(sp_audio *a); /* 1 once if a route change dropped the speaker */

#endif

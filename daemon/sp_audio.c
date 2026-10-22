#include "sp_audio.h"
#include "sp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>

#include <AudioToolbox/AudioToolbox.h>
#include <AudioUnit/AudioUnit.h>

/* iOS 6 ships the C AudioSession API (deprecated later). It is how a non-UIKit
   process configures the session for record+playback. Its callbacks arrive on
   the main run loop, which main.c pumps from its poll loop. */

#define HW_RATE 8000.0        /* client side: G.711 is 8 kHz either way */
#define CAP_MAX (120 * 8000)  /* up to 2 minutes of each direction */
#define CAP_MIC_PATH "/var/mobile/SIPPhone-mic.wav"
#define CAP_SPK_PATH "/var/mobile/SIPPhone-spk.wav"
#define SP_VOICECHAT_MODE 1   /* VPIO needs VoiceChat: in Default mode mediaserverd logs "invalid route/mode pair"
                                 and skips the voice-processing route. Side effect: Bluetooth HFP allowed. */

struct sp_audio {
    sp_audio_tx tx;
    void       *ctx;
    AudioUnit   unit;
    int         running;
    int         muted;
    int         speaker;
    int         tone;           /* SP_AU_TONE_* */
    double      tone_phase1, tone_phase2;
    long        tone_pos;       /* samples since the tone started (for cadence) */
    int         interrupted;    /* inside a begin/end interruption pair */
    /* debug counters (written on the IO thread, read under the lock) */
    uint32_t    in_cbs, out_cbs, render_errs;
    int32_t     last_render_err;
    int         mic_peak;       /* max |sample| captured since the last snapshot */
    int         route_changed;  /* a route change dropped the speaker override */
    int         mode;           /* SP_AU_MODE_* */
    int         bt_allowed;     /* Settings: Bluetooth headset may carry calls */
    int         bt_failed;      /* this call: the Bluetooth route stalled, stay on the phone */
    uint32_t    wd_last_in_cbs; /* watchdog: callbacks seen at the previous tick */
    int         wd_stalled;     /* watchdog: consecutive ticks without callbacks */
    int         bypass_active;  /* the running unit has voice processing bypassed */
    int         rebuild;        /* a route change wants the other bypass state */
    int         mic_fixed;      /* mic delivered as 8.24 fixed point (headroom past full scale) */
    float       agc_gain, agc_env;
    uint32_t    mic_clips;      /* samples at/over full scale before our gain (debug) */
    float       agc_min_gain;   /* lowest gain since the last snapshot (debug) */
    int         capture;        /* record the call to WAV */
    int16_t    *cap_mic, *cap_spk;
    uint32_t    cap_mic_n, cap_spk_n;
    pthread_mutex_t lock;
    sp_rtp      rtp;

    /* mic framer: accumulate hardware callback samples into 160-sample frames */
    int16_t     mic_acc[SP_SAMPLES * 4];
    int         mic_fill;

    /* playout: iOS asks for 128/186/256 frames, never exactly 160, so keep the
       rest of the last pulled 20 ms frame for the next callback */
    int16_t     play_buf[SP_SAMPLES];
    int         play_pos;       /* SP_SAMPLES = empty */

    /* a scratch buffer for the input render pull */
    AudioBufferList *in_abl;
    int32_t     in_raw[SP_SAMPLES * 8];     /* 8.24 mic samples */
    int16_t     in_scratch[SP_SAMPLES * 8]; /* after our gain/limiter: what gets sent */
};

static void set_format(AudioUnit unit, AudioUnitScope scope, AudioUnitElement el)
{
    AudioStreamBasicDescription f;
    memset(&f, 0, sizeof f);
    f.mSampleRate = HW_RATE;
    f.mFormatID = kAudioFormatLinearPCM;
    f.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    f.mFramesPerPacket = 1;
    f.mChannelsPerFrame = 1;
    f.mBitsPerChannel = 16;
    f.mBytesPerFrame = 2;
    f.mBytesPerPacket = 2;
    AudioUnitSetProperty(unit, kAudioUnitProperty_StreamFormat, scope, el, &f, sizeof f);
}

/* Mic side as the AU canonical 8.24 fixed point: a loud voice with no voice
   processing goes past full scale, and int16 would clip it inside the unit.
   Returns 1 if accepted, 0 if we fell back to int16. */
static int set_mic_format(AudioUnit unit)
{
    AudioStreamBasicDescription f;
    memset(&f, 0, sizeof f);
    f.mSampleRate = HW_RATE;
    f.mFormatID = kAudioFormatLinearPCM;
    f.mFormatFlags = kAudioFormatFlagsAudioUnitCanonical;
    f.mFramesPerPacket = 1;
    f.mChannelsPerFrame = 1;
    f.mBitsPerChannel = 32;
    f.mBytesPerFrame = 4;
    f.mBytesPerPacket = 4;
    if (AudioUnitSetProperty(unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Output, 1,
                             &f, sizeof f) == noErr)
        return 1;
    set_format(unit, kAudioUnitScope_Output, 1);
    return 0;
}

/* Gain + soft limiter on one block of mic samples (full scale = 1.0).
   Without voice processing there is no AGC, and a loud talker clipped about 1%
   of samples; with it, this is a near no-op (its output already peaks ~0.9). */
static void mic_agc(sp_audio *a, const float *x, int16_t *out, UInt32 n)
{
    float target = a->bypass_active ? 0.5f : 0.89f;
    float gmax = a->bypass_active ? 1.5f : 1.0f;
    float pk = 0;
    for (UInt32 k = 0; k < n; k++) {
        float ax = fabsf(x[k]);
        if (ax > pk)
            pk = ax;
        if (ax >= 0.999f)
            a->mic_clips++;
    }
    a->agc_env = pk > a->agc_env ? pk : a->agc_env * 0.99f + pk * 0.01f;   /* instant attack, ~1.6 s release */
    float g = target / (a->agc_env > 1e-4f ? a->agc_env : 1e-4f);
    if (g > gmax)
        g = gmax;
    if (g < a->agc_gain)
        a->agc_gain = g;                                  /* duck at once (this block's peak included) */
    else
        a->agc_gain += (g - a->agc_gain) * 0.02f;         /* recover slowly */
    if (a->agc_gain < a->agc_min_gain)
        a->agc_min_gain = a->agc_gain;
    for (UInt32 k = 0; k < n; k++) {
        float y = x[k] * a->agc_gain;
        float ay = fabsf(y);
        if (ay > 0.75f) {                                 /* soft knee instead of a hard clip */
            float lim = 0.75f + 0.24f * tanhf((ay - 0.75f) / 0.24f);
            y = y < 0 ? -lim : lim;
        }
        out[k] = (int16_t)(y * 32767.0f);
    }
}

/* Fill `n` samples of a US call-progress tone with cadence; advances state. */
static void gen_tone(sp_audio *a, int16_t *dst, int n)
{
    double f1, f2, onp, offp;
    if (a->tone == SP_AU_TONE_BUSY) {
        f1 = 480; f2 = 620; onp = 0.5; offp = 0.5;     /* US busy */
    } else {
        f1 = 440; f2 = 480; onp = 2.0; offp = 4.0;     /* US ringback */
    }
    long period = (long)((onp + offp) * SP_CLOCK);
    long on = (long)(onp * SP_CLOCK);
    for (int i = 0; i < n; i++) {
        long ph = (a->tone_pos + i) % period;
        int16_t s = 0;
        if (ph < on) {
            double v = sin(a->tone_phase1) + sin(a->tone_phase2);
            s = (int16_t)(v * 7000);
        }
        a->tone_phase1 += 2 * M_PI * f1 / SP_CLOCK;
        a->tone_phase2 += 2 * M_PI * f2 / SP_CLOCK;
        if (a->tone_phase1 > 2 * M_PI) a->tone_phase1 -= 2 * M_PI;
        if (a->tone_phase2 > 2 * M_PI) a->tone_phase2 -= 2 * M_PI;
        dst[i] = s;
    }
    a->tone_pos += n;
}

/* output bus (0): the system asks us for speaker/earpiece samples */
static OSStatus render_cb(void *ref, AudioUnitRenderActionFlags *flags, const AudioTimeStamp *ts,
                          UInt32 bus, UInt32 frames, AudioBufferList *io)
{
    (void)ts;
    (void)bus;
    sp_audio *a = ref;
    int16_t *dst = io->mBuffers[0].mData;
    pthread_mutex_lock(&a->lock);
    a->out_cbs++;
    if (a->tone != SP_AU_TONE_NONE) {
        gen_tone(a, dst, (int)frames);
    } else {
        UInt32 done = 0;
        while (done < frames) {
            if (a->play_pos >= SP_SAMPLES) {          /* pull a new frame only when the last is used up */
                sp_rtp_playout(&a->rtp, a->play_buf);
                a->play_pos = 0;
            }
            UInt32 avail = (UInt32)(SP_SAMPLES - a->play_pos);
            UInt32 take = frames - done;
            if (take > avail)
                take = avail;
            memcpy(dst + done, a->play_buf + a->play_pos, take * sizeof(int16_t));
            a->play_pos += (int)take;
            done += take;
        }
    }
    if (a->cap_spk && a->cap_spk_n + frames <= CAP_MAX) {
        memcpy(a->cap_spk + a->cap_spk_n, dst, frames * sizeof(int16_t));
        a->cap_spk_n += frames;
    }
    pthread_mutex_unlock(&a->lock);
    io->mBuffers[0].mDataByteSize = frames * sizeof(int16_t);
    if (flags)
        *flags = 0;
    return noErr;
}

/* input bus (1): mic samples are ready to pull */
static OSStatus input_cb(void *ref, AudioUnitRenderActionFlags *flags, const AudioTimeStamp *ts,
                         UInt32 bus, UInt32 frames, AudioBufferList *io)
{
    (void)io;
    sp_audio *a = ref;
    if (frames > SP_SAMPLES * 8)
        frames = SP_SAMPLES * 8;
    int fixed = a->mic_fixed;
    a->in_abl->mNumberBuffers = 1;
    a->in_abl->mBuffers[0].mNumberChannels = 1;
    a->in_abl->mBuffers[0].mDataByteSize = frames * (fixed ? sizeof(int32_t) : sizeof(int16_t));
    a->in_abl->mBuffers[0].mData = fixed ? (void *)a->in_raw : (void *)a->in_scratch;
    OSStatus st = AudioUnitRender(a->unit, flags, ts, bus, frames, a->in_abl);
    pthread_mutex_lock(&a->lock);
    a->in_cbs++;
    if (st != noErr) {
        a->render_errs++;
        a->last_render_err = (int32_t)st;
        pthread_mutex_unlock(&a->lock);
        return st;
    }
    {
        float xf[SP_SAMPLES * 8];
        if (fixed)
            for (UInt32 k = 0; k < frames; k++)
                xf[k] = (float)a->in_raw[k] * (1.0f / 16777216.0f);
        else
            for (UInt32 k = 0; k < frames; k++)
                xf[k] = (float)a->in_scratch[k] * (1.0f / 32768.0f);
        mic_agc(a, xf, a->in_scratch, frames);
    }
    if (a->cap_mic && a->cap_mic_n + frames <= CAP_MAX) {   /* raw mic, before mute/ringback */
        memcpy(a->cap_mic + a->cap_mic_n, a->in_scratch, frames * sizeof(int16_t));
        a->cap_mic_n += frames;
    }
    for (UInt32 k = 0; k < frames; k++) {
        int v = a->in_scratch[k];
        if (v < 0)
            v = -v;
        if (v > a->mic_peak)
            a->mic_peak = v;
    }
    if (a->tone == SP_AU_TONE_BUSY) {                 /* busy: send nothing */
        pthread_mutex_unlock(&a->lock);
        return noErr;
    }
    if (a->muted || a->tone == SP_AU_TONE_RINGBACK)   /* ringback: silence keeps the RTP NAT path open */
        memset(a->in_scratch, 0, frames * sizeof(int16_t));
    /* accumulate into 160-sample frames and emit RTP for each */
    UInt32 i = 0;
    while (i < frames) {
        int space = SP_SAMPLES - a->mic_fill;
        int take = (int)(frames - i) < space ? (int)(frames - i) : space;
        memcpy(a->mic_acc + a->mic_fill, a->in_scratch + i, take * sizeof(int16_t));
        a->mic_fill += take;
        i += take;
        if (a->mic_fill == SP_SAMPLES) {
            uint8_t pkt[256];
            int n = sp_rtp_build(&a->rtp, a->mic_acc, pkt, sizeof pkt);
            a->mic_fill = 0;
            if (n > 0 && a->tx) {
                pthread_mutex_unlock(&a->lock);
                a->tx(a->ctx, pkt, n);          /* sendto outside the lock */
                pthread_mutex_lock(&a->lock);
            }
        }
    }
    pthread_mutex_unlock(&a->lock);
    return noErr;
}

static void apply_route(sp_audio *a)
{
    UInt32 route = a->speaker ? kAudioSessionOverrideAudioRoute_Speaker
                              : kAudioSessionOverrideAudioRoute_None;
    AudioSessionSetProperty(kAudioSessionProperty_OverrideAudioRoute, sizeof route, &route);
}

static void session_config(sp_audio *a)
{
    UInt32 category = kAudioSessionCategory_PlayAndRecord;
    AudioSessionSetProperty(kAudioSessionProperty_AudioCategory, sizeof category, &category);
#if SP_VOICECHAT_MODE
    UInt32 mode = kAudioSessionMode_VoiceChat;        /* VoIP mode; side effect: Bluetooth HFP input allowed */
    AudioSessionSetProperty(kAudioSessionProperty_Mode, sizeof mode, &mode);
#endif
    UInt32 allowMix = 0;
    AudioSessionSetProperty(kAudioSessionProperty_OverrideCategoryMixWithOthers, sizeof allowMix, &allowMix);
    /* let a connected Bluetooth headset (AirPods over HFP) carry the call like the stock
       phone does; PlayAndRecord stays on the earpiece without this, VoiceChat or not */
    UInt32 btIn = a->bt_allowed && !a->bt_failed;
    OSStatus bs = AudioSessionSetProperty(kAudioSessionProperty_OverrideCategoryEnableBluetoothInput,
                                          sizeof btIn, &btIn);
    if (bs != noErr)
        sp_log("audio: setting Bluetooth input to %u failed: %d", (unsigned)btIn, (int)bs);
    Float32 dur = 0.02f;   /* ask for 20 ms IO; render_cb copes with whatever we get */
    AudioSessionSetProperty(kAudioSessionProperty_PreferredHardwareIOBufferDuration, sizeof dur, &dur);
    Float64 rate = HW_RATE;   /* 16 kHz (wideband tuning) measured no better on 2026-10-12 */
    AudioSessionSetProperty(kAudioSessionProperty_PreferredHardwareSampleRate, sizeof rate, &rate);
}

static void unit_dispose(sp_audio *a)
{
    if (!a->unit)
        return;
    AudioOutputUnitStop(a->unit);          /* waits until the IO thread has left the callbacks */
    AudioUnitUninitialize(a->unit);
    AudioComponentInstanceDispose(a->unit);
    a->unit = NULL;
}

static void log_hw(void)
{
    Float64 hr = 0;
    Float32 hb = 0;
    UInt32 sz = sizeof hr;
    AudioSessionGetProperty(kAudioSessionProperty_CurrentHardwareSampleRate, &sz, &hr);
    sz = sizeof hb;
    AudioSessionGetProperty(kAudioSessionProperty_CurrentHardwareIOBufferDuration, &sz, &hb);
    UInt32 inAvail = 0;
    sz = sizeof inAvail;
    AudioSessionGetProperty(kAudioSessionProperty_AudioInputAvailable, &sz, &inAvail);
    char route[64] = "?";
    CFStringRef r = NULL;
    sz = sizeof r;
    if (AudioSessionGetProperty(kAudioSessionProperty_AudioRoute, &sz, &r) == noErr && r) {
        CFStringGetCString(r, route, sizeof route, kCFStringEncodingUTF8);
        CFRelease(r);
    }
    sp_log("audio: hw rate=%.0f io=%.4f s, input available=%u, route=%s", hr, hb, (unsigned)inAvail, route);
}

static void log_format(AudioUnit unit, AudioUnitScope scope, AudioUnitElement el, const char *what)
{
    AudioStreamBasicDescription f;
    UInt32 sz = sizeof f;
    memset(&f, 0, sizeof f);
    OSStatus st = AudioUnitGetProperty(unit, kAudioUnitProperty_StreamFormat, scope, el, &f, &sz);
    sp_log("audio: %s format st=%d rate=%.0f ch=%u bits=%u flags=0x%x", what, (int)st, f.mSampleRate,
           (unsigned)f.mChannelsPerFrame, (unsigned)f.mBitsPerChannel, (unsigned)f.mFormatFlags);
}

static void current_route(char *out, size_t n)
{
    CFStringRef r = NULL;
    UInt32 sz = sizeof r;
    sp_strlcpy(out, "?", n);
    if (AudioSessionGetProperty(kAudioSessionProperty_AudioRoute, &sz, &r) == noErr && r) {
        CFStringGetCString(r, out, (CFIndex)n, kCFStringEncodingUTF8);
        CFRelease(r);
    }
}

/* Voice processing off only where its echo suppressor hurts more than it helps:
   the built-in earpiece (little acoustic echo, and measured choppy). */
static int want_bypass(sp_audio *a)
{
    if (a->mode == SP_AU_MODE_RAW)
        return 1;
    if (a->mode == SP_AU_MODE_PROCESSED || a->speaker)
        return 0;
    char route[64];
    current_route(route, sizeof route);
    if (strstr(route, "Receiver"))
        return 1;
    /* "SpeakerAndMicrophone" with our speaker override off is the ringtone's route
       still in place at answer; the earpiece follows a moment later. Headsets,
       Bluetooth, line out and docks keep voice processing. */
    return strstr(route, "Speaker") && !strstr(route, "BT") && !strstr(route, "Head");
}

/* Build, activate and start a fresh VPIO unit. Never touches a->rtp (keeps codec/SSRC/DTMF).
   Order matters for the mic: the PlayAndRecord session must be active before the
   unit is created/initialised, or the input element can come up with no device. */
static int restart_unit_ex(sp_audio *a, int full)
{
    unit_dispose(a);
    a->rebuild = 0;
    if (full) {                           /* a route rebuild keeps the live session as is (faster) */
        session_config(a);
        OSStatus act = AudioSessionSetActive(true);
        if (act != noErr) {
            sp_log("audio: AudioSessionSetActive(true) failed: %d", (int)act);
            return -1;
        }
    }
    AudioComponentDescription desc;
    memset(&desc, 0, sizeof desc);
    desc.componentType = kAudioUnitType_Output;
    desc.componentSubType = kAudioUnitSubType_VoiceProcessingIO;
    desc.componentManufacturer = kAudioUnitManufacturer_Apple;
    AudioComponent comp = AudioComponentFindNext(NULL, &desc);
    if (!comp || AudioComponentInstanceNew(comp, &a->unit) != noErr) {
        a->unit = NULL;
        sp_log("audio: no VoiceProcessingIO unit");
        AudioSessionSetActiveWithFlags(false, kAudioSessionSetActiveFlag_NotifyOthersOnDeactivation);
        return -1;
    }
    UInt32 one = 1;
    AudioUnitSetProperty(a->unit, kAudioOutputUnitProperty_EnableIO, kAudioUnitScope_Input, 1,
                         &one, sizeof one);
    AudioUnitSetProperty(a->unit, kAudioOutputUnitProperty_EnableIO, kAudioUnitScope_Output, 0,
                         &one, sizeof one);
    a->bypass_active = want_bypass(a);
    if (a->bypass_active) {
        UInt32 bypass = 1;                            /* no echo cancel / AGC / noise suppression */
        OSStatus bs = AudioUnitSetProperty(a->unit, kAUVoiceIOProperty_BypassVoiceProcessing,
                                           kAudioUnitScope_Global, 0, &bypass, sizeof bypass);
        if (bs != noErr)
            a->bypass_active = 0;
    }
    a->agc_gain = 1.0f;
    a->agc_min_gain = 1.0f;
    a->agc_env = 0;
    a->mic_fixed = set_mic_format(a->unit);           /* mic side we read */
    {
        char route[64];
        current_route(route, sizeof route);
        sp_log("audio: building unit: voice processing %s (mode %d, route %s, speaker %d), mic %s",
               a->bypass_active ? "OFF" : "on", a->mode, route, a->speaker, a->mic_fixed ? "8.24" : "int16");
    }
    set_format(a->unit, kAudioUnitScope_Input, 0);    /* speaker side we write */
    AURenderCallbackStruct out_cb = { render_cb, a };
    AudioUnitSetProperty(a->unit, kAudioUnitProperty_SetRenderCallback, kAudioUnitScope_Input, 0,
                         &out_cb, sizeof out_cb);
    AURenderCallbackStruct in_cb = { input_cb, a };
    AudioUnitSetProperty(a->unit, kAudioOutputUnitProperty_SetInputCallback, kAudioUnitScope_Global, 1,
                         &in_cb, sizeof in_cb);
    OSStatus st = AudioUnitInitialize(a->unit);
    if (st != noErr) {
        sp_log("audio: AudioUnitInitialize failed: %d", (int)st);
        unit_dispose(a);
        AudioSessionSetActiveWithFlags(false, kAudioSessionSetActiveFlag_NotifyOthersOnDeactivation);
        return -1;
    }
    log_format(a->unit, kAudioUnitScope_Input, 1, "mic hw");
    log_format(a->unit, kAudioUnitScope_Output, 1, "mic client");
    log_format(a->unit, kAudioUnitScope_Input, 0, "speaker client");
    apply_route(a);
    st = AudioOutputUnitStart(a->unit);
    if (st != noErr) {
        sp_log("audio: AudioOutputUnitStart failed: %d", (int)st);
        unit_dispose(a);
        AudioSessionSetActiveWithFlags(false, kAudioSessionSetActiveFlag_NotifyOthersOnDeactivation);
        return -1;
    }
    log_hw();
    return 0;
}

static int restart_unit(sp_audio *a)
{
    return restart_unit_ex(a, 1);
}

static int light_resume(sp_audio *a)
{
    if (!a->unit || AudioSessionSetActive(true) != noErr)
        return -1;
    apply_route(a);                       /* interruptions clear the speaker override */
    return AudioOutputUnitStart(a->unit) == noErr ? 0 : -1;
}

static void session_interruption(void *ref, UInt32 state)
{
    sp_audio *a = ref;
    if (state == kAudioSessionBeginInterruption) {
        a->interrupted = 1;
        if (a->unit)
            AudioOutputUnitStop(a->unit);
        sp_log("audio: interruption began");
        return;
    }
    a->interrupted = 0;
    if (!a->running)
        return;
    if (light_resume(a) == 0)
        sp_log("audio: resumed after interruption");
    else if (restart_unit(a) != 0)
        a->running = 0;                   /* main loop retries a full start */
}

static void session_property(void *ref, AudioSessionPropertyID id, UInt32 size, const void *val)
{
    sp_audio *a = ref;
    (void)size;
    if (id == kAudioSessionProperty_ServerDied) {
        sp_log("audio: media server died");
        if (a->unit) {                    /* dead instance: dispose only, no Stop/Uninitialize */
            AudioComponentInstanceDispose(a->unit);
            a->unit = NULL;
        }
        if (a->running && restart_unit(a) != 0)
            a->running = 0;
        return;
    }
    if (id != kAudioSessionProperty_AudioRouteChange || !val)
        return;
    CFNumberRef r = CFDictionaryGetValue((CFDictionaryRef)val, kAudioSession_RouteChangeKey_Reason);
    SInt32 reason = 0;
    if (r)
        CFNumberGetValue(r, kCFNumberSInt32Type, &reason);
    char route[64] = "?";
    CFStringRef cur = NULL;
    UInt32 sz = sizeof cur;
    if (AudioSessionGetProperty(kAudioSessionProperty_AudioRoute, &sz, &cur) == noErr && cur) {
        CFStringGetCString(cur, route, sizeof route, kCFStringEncodingUTF8);
        CFRelease(cur);
    }
    sp_log("audio: route change reason %d -> %s (spk sample %u)", (int)reason, route, a->cap_spk_n);
    log_hw();
    if (a->running && a->unit && !a->interrupted && want_bypass(a) != a->bypass_active) {
        a->rebuild = 1;                   /* done from the main loop, not inside this listener */
        sp_log("audio: route wants voice processing %s: rebuilding", a->bypass_active ? "on" : "OFF");
    }
    if ((reason == kAudioSessionRouteChangeReason_NewDeviceAvailable ||
         reason == kAudioSessionRouteChangeReason_OldDeviceUnavailable) && a->speaker) {
        a->speaker = 0;                   /* the override was dropped; match stock Phone, don't force it back */
        a->route_changed = 1;
    }
}

sp_audio *sp_audio_new(sp_audio_tx tx, void *ctx)
{
    sp_audio *a = calloc(1, sizeof *a);
    a->tx = tx;
    a->ctx = ctx;
    a->play_pos = SP_SAMPLES;
    pthread_mutex_init(&a->lock, NULL);
    a->in_abl = calloc(1, sizeof(AudioBufferList));
    OSStatus st = AudioSessionInitialize(CFRunLoopGetMain(), kCFRunLoopDefaultMode, session_interruption, a);
    if (st != noErr)
        sp_log("audio: AudioSessionInitialize failed: %d", (int)st);
    AudioSessionAddPropertyListener(kAudioSessionProperty_AudioRouteChange, session_property, a);
    AudioSessionAddPropertyListener(kAudioSessionProperty_ServerDied, session_property, a);
    return a;
}

void sp_audio_free(sp_audio *a)
{
    if (!a)
        return;
    sp_audio_stop(a);
    free(a->cap_mic);
    free(a->cap_spk);
    free(a->in_abl);
    pthread_mutex_destroy(&a->lock);
    free(a);
}

int sp_audio_start(sp_audio *a, int codec_pt, int dtmf_pt, int sending, int recving)
{
    if (a->running || a->unit)            /* also cleans up a half-built unit from a failed start */
        sp_audio_stop(a);
    pthread_mutex_lock(&a->lock);
    sp_rtp_init(&a->rtp, codec_pt, dtmf_pt);
    sp_rtp_set_dir(&a->rtp, sending, recving);
    a->mic_fill = 0;
    a->play_pos = SP_SAMPLES;
    a->in_cbs = a->out_cbs = a->render_errs = 0;
    a->last_render_err = 0;
    a->mic_peak = 0;
    pthread_mutex_unlock(&a->lock);
    a->interrupted = 0;
    a->route_changed = 0;
    a->bt_failed = 0;
    a->wd_last_in_cbs = 0;
    a->wd_stalled = 0;
    if (a->capture && !a->cap_mic) {
        a->cap_mic = malloc(CAP_MAX * sizeof(int16_t));
        a->cap_spk = malloc(CAP_MAX * sizeof(int16_t));
        if (!a->cap_mic || !a->cap_spk) {
            free(a->cap_mic);
            free(a->cap_spk);
            a->cap_mic = a->cap_spk = NULL;
        }
    } else if (!a->capture && a->cap_mic) {
        free(a->cap_mic);                  /* the IO callbacks record whenever these exist */
        free(a->cap_spk);
        a->cap_mic = a->cap_spk = NULL;
    }
    a->cap_mic_n = a->cap_spk_n = 0;
    if (restart_unit(a) != 0)
        return -1;
    a->running = 1;
    sp_log("audio: started pt=%d dtmf=%d dir=%d/%d mode=%d vp=%s capture=%d", codec_pt, dtmf_pt, sending,
           recving, a->mode, a->bypass_active ? "off" : "on", a->cap_mic != NULL);
    return 0;
}

void sp_audio_reconfigure(sp_audio *a, int codec_pt, int dtmf_pt, int sending, int recving)
{
    pthread_mutex_lock(&a->lock);
    sp_rtp_init(&a->rtp, codec_pt, dtmf_pt);
    sp_rtp_set_dir(&a->rtp, sending, recving);
    a->mic_fill = 0;
    a->play_pos = SP_SAMPLES;
    a->tone = SP_AU_TONE_NONE;
    pthread_mutex_unlock(&a->lock);
    sp_log("audio: reconfigured pt=%d dtmf=%d dir=%d/%d", codec_pt, dtmf_pt, sending, recving);
}

void sp_audio_update_dir(sp_audio *a, int sending, int recving)
{
    pthread_mutex_lock(&a->lock);
    sp_rtp_set_dir(&a->rtp, sending, recving);
    pthread_mutex_unlock(&a->lock);
}

void sp_audio_set_tone(sp_audio *a, int tone)
{
    pthread_mutex_lock(&a->lock);
    if (a->tone != tone) {
        a->tone = tone;
        a->tone_pos = 0;
        a->tone_phase1 = a->tone_phase2 = 0;
        a->play_pos = SP_SAMPLES;          /* no stale audio after a tone ends */
    }
    pthread_mutex_unlock(&a->lock);
}

static void put32(FILE *f, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    fwrite(b, 1, 4, f);
}

static void put16(FILE *f, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    fwrite(b, 1, 2, f);
}

/* 8 kHz mono 16-bit PCM WAV (the device is little-endian, like WAV) */
static void write_wav(const char *path, const int16_t *pcm, uint32_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    fwrite("RIFF", 1, 4, f);
    put32(f, 36 + n * 2);
    fwrite("WAVEfmt ", 1, 8, f);
    put32(f, 16);
    put16(f, 1);
    put16(f, 1);
    put32(f, 8000);
    put32(f, 16000);
    put16(f, 2);
    put16(f, 16);
    fwrite("data", 1, 4, f);
    put32(f, n * 2);
    fwrite(pcm, 2, n, f);
    fclose(f);
}

void sp_audio_stop(sp_audio *a)
{
    if (!a->running && !a->unit)
        return;
    a->running = 0;
    unit_dispose(a);                       /* the IO thread is out of the callbacks after this */
    AudioSessionSetActiveWithFlags(false, kAudioSessionSetActiveFlag_NotifyOthersOnDeactivation);
    a->interrupted = 0;
    if (a->cap_mic && a->cap_mic_n) {
        write_wav(CAP_MIC_PATH, a->cap_mic, a->cap_mic_n);
        write_wav(CAP_SPK_PATH, a->cap_spk, a->cap_spk_n);
        sp_log("audio: recorded %u mic / %u speaker samples to /var/mobile/SIPPhone-*.wav",
               a->cap_mic_n, a->cap_spk_n);
    }
    a->cap_mic_n = a->cap_spk_n = 0;
    sp_log("audio: stopped");
}

void sp_audio_set_bluetooth(sp_audio *a, int on)
{
    a->bt_allowed = on;
}

void sp_audio_set_mode(sp_audio *a, int mode)
{
    if (mode < SP_AU_MODE_AUTO || mode > SP_AU_MODE_RAW)
        mode = SP_AU_MODE_AUTO;
    a->mode = mode;
}

void sp_audio_service(sp_audio *a)
{
    if (!a->rebuild || !a->running || a->interrupted)
        return;
    sp_log("audio: rebuilding unit for the new route");
    if (restart_unit_ex(a, 0) != 0 && restart_unit(a) != 0) {
        a->running = 0;                   /* main loop retries a full start */
        return;
    }
    pthread_mutex_lock(&a->lock);
    int dropped = sp_rtp_drop_backlog(&a->rtp);   /* audio that queued during the rebuild is stale */
    a->play_pos = SP_SAMPLES;
    pthread_mutex_unlock(&a->lock);
    if (dropped)
        sp_log("audio: dropped %d ms of backlog after the rebuild", dropped / 8);
}

void sp_audio_delete_captures(void)
{
    unlink(CAP_MIC_PATH);
    unlink(CAP_SPK_PATH);
}

void sp_audio_set_capture(sp_audio *a, int on)
{
    a->capture = on;                       /* buffers are allocated at the next start */
}

void sp_audio_set_mute(sp_audio *a, int muted)
{
    pthread_mutex_lock(&a->lock);
    a->muted = muted;
    pthread_mutex_unlock(&a->lock);
}

int sp_audio_set_speaker(sp_audio *a, int on)
{
    if (a->running && on != a->speaker)
        sp_log("audio: speaker %s (spk sample %u)", on ? "on" : "off", a->cap_spk_n);
    a->speaker = on;
    if (a->running)
        apply_route(a);
    return 0;
}

void sp_audio_send_dtmf(sp_audio *a, char digit)
{
    pthread_mutex_lock(&a->lock);
    sp_rtp_send_dtmf(&a->rtp, digit);
    pthread_mutex_unlock(&a->lock);
}

void sp_audio_rtp_in(sp_audio *a, const uint8_t *pkt, int len)
{
    pthread_mutex_lock(&a->lock);
    uint32_t before = a->rtp.rx_pkts;
    sp_rtp_recv(&a->rtp, pkt, (size_t)len);
    if (a->tone == SP_AU_TONE_RINGBACK && a->rtp.rx_pkts != before) {
        a->tone = SP_AU_TONE_NONE;        /* real early media arrived: play it; mic opens next frame */
        a->play_pos = SP_SAMPLES;
    }
    pthread_mutex_unlock(&a->lock);
}

void sp_audio_stats(sp_audio *a, uint32_t *tx, uint32_t *rx, uint32_t *lost)
{
    pthread_mutex_lock(&a->lock);
    if (tx) *tx = a->rtp.tx_pkts;
    if (rx) *rx = a->rtp.rx_pkts;
    if (lost) *lost = a->rtp.rx_lost;
    pthread_mutex_unlock(&a->lock);
}

int sp_audio_is_running(sp_audio *a)
{
    return a->running;
}

void sp_audio_debug(sp_audio *a, char *out, size_t n)
{
    pthread_mutex_lock(&a->lock);
    snprintf(out, n, "in_cb=%u out_cb=%u render_err=%u(last %d) mic_peak=%d muted=%d tone=%d "
             "tx=%u rx=%u lost=%u late=%u resync=%u trim=%u queued=%d send=%d vp=%s clips=%u gain=%.2f",
             (unsigned)a->in_cbs, (unsigned)a->out_cbs, (unsigned)a->render_errs,
             (int)a->last_render_err, a->mic_peak, a->muted, a->tone, (unsigned)a->rtp.tx_pkts,
             (unsigned)a->rtp.rx_pkts, (unsigned)a->rtp.rx_lost, (unsigned)a->rtp.rx_oop,
             (unsigned)a->rtp.rx_resync, (unsigned)a->rtp.rx_trim,
             (int)(int32_t)(a->rtp.rx_end_ts - a->rtp.play_ts), a->rtp.sending,
             a->bypass_active ? "off" : "on", (unsigned)a->mic_clips, a->agc_min_gain);
    a->mic_peak = 0;
    a->mic_clips = 0;
    a->agc_min_gain = a->agc_gain;
    pthread_mutex_unlock(&a->lock);
}

int sp_audio_take_route_change(sp_audio *a)
{
    int r = a->route_changed;
    a->route_changed = 0;
    return r;
}

void sp_audio_watchdog(sp_audio *a)
{
    if (!a->running || !a->unit)
        return;
    /* A unit can report running while mediaserverd has no working device (an AirPods
       SCO link that never comes up): no callbacks at all. Three silent ticks = stalled. */
    pthread_mutex_lock(&a->lock);
    uint32_t cbs = a->in_cbs + a->out_cbs;
    pthread_mutex_unlock(&a->lock);
    if (!a->interrupted && cbs == a->wd_last_in_cbs) {
        if (++a->wd_stalled >= 3) {
            char route[64];
            current_route(route, sizeof route);
            a->wd_stalled = 0;
            if (strstr(route, "BT"))
                a->bt_failed = 1;         /* stay on the phone for the rest of this call */
            sp_log("audio: IO stalled (route %s): rebuilding%s", route,
                   a->bt_failed ? " without Bluetooth" : "");
            if (restart_unit(a) != 0)
                a->running = 0;
            else {
                pthread_mutex_lock(&a->lock);
                sp_rtp_drop_backlog(&a->rtp);
                a->play_pos = SP_SAMPLES;
                pthread_mutex_unlock(&a->lock);
            }
            return;
        }
    } else {
        a->wd_stalled = 0;
    }
    a->wd_last_in_cbs = cbs;
    UInt32 on = 1, sz = sizeof on;
    if (AudioUnitGetProperty(a->unit, kAudioOutputUnitProperty_IsRunning, kAudioUnitScope_Global, 0,
                             &on, &sz) != noErr || on)
        return;
    if (light_resume(a) == 0) {           /* covers interrupters that never send end-interruption */
        a->interrupted = 0;
        sp_log("audio: watchdog restarted the unit");
    } else if (!a->interrupted && restart_unit(a) != 0) {
        a->running = 0;                   /* don't rebuild in a loop while a cellular call holds the session */
    }
}

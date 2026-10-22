TARGET = iphone:clang:6.1:6.0
ARCHS = armv7 armv7s

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SIPPhoneSB
SIPPhoneSB_FILES = Tweak.xm ../common/SPClient.m
SIPPhoneSB_CFLAGS = -fobjc-arc -I../common
SIPPhoneSB_FRAMEWORKS = UIKit Foundation CoreGraphics AudioToolbox AVFoundation AddressBook QuartzCore

include $(THEOS)/makefiles/tweak.mk

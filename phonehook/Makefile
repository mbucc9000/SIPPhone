TARGET = iphone:clang:6.1:6.0
ARCHS = armv7 armv7s

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SIPPhonePhone
SIPPhonePhone_FILES = Tweak.xm ../common/SPClient.m
SIPPhonePhone_CFLAGS = -fobjc-arc -I../common
SIPPhonePhone_FRAMEWORKS = UIKit Foundation

include $(THEOS)/makefiles/tweak.mk

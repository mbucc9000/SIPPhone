TARGET = iphone:clang:6.1:6.0
ARCHS = armv7 armv7s

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = SIPPhonePrefs
SIPPhonePrefs_FILES = SIPPhonePrefs.m
SIPPhonePrefs_CFLAGS = -fobjc-arc -I../common
SIPPhonePrefs_FRAMEWORKS = UIKit Foundation
SIPPhonePrefs_PRIVATE_FRAMEWORKS = Preferences
SIPPhonePrefs_INSTALL_PATH = /Library/PreferenceBundles
SIPPhonePrefs_RESOURCE_DIRS = Resources

include $(THEOS)/makefiles/bundle.mk

TARGET = iphone:clang:6.1:6.0
ARCHS = armv7 armv7s

include $(THEOS)/makefiles/common.mk

SUBPROJECTS = daemon phonehook springboardhook sipphoneprefs

include $(THEOS)/makefiles/aggregate.mk

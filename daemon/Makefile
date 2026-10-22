TARGET = iphone:clang:6.1:6.0
ARCHS = armv7 armv7s

include $(THEOS)/makefiles/common.mk

TOOL_NAME = sipphoned
sipphoned_FILES = main.c sp_util.c sp_md5.c sp_sip.c sp_sdp.c sp_rtp.c sp_ua.c sp_audio.c
sipphoned_CFLAGS = -std=c11 -Wall -I../common -fno-objc-arc
sipphoned_FRAMEWORKS = CoreFoundation AudioToolbox
sipphoned_INSTALL_PATH = /usr/libexec

include $(THEOS)/makefiles/tool.mk

after-install::
	install.exec "launchctl load /Library/LaunchDaemons/com.mbucc9000.sipphoned.plist 2>/dev/null; launchctl stop com.mbucc9000.sipphoned; launchctl start com.mbucc9000.sipphoned"

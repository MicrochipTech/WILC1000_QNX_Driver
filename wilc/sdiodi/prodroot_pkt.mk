
# We link the stack with -E so a lot of the undefined
# references get resolved from the stack itself.  If
# you want them listed at link time, turn off
# --allow-shlib-undefined and replace with --warn-once
# if desired.

#LDFLAGS+=-Wl,--warn-once
LDFLAGS+=-Wl,--allow-shlib-undefined


#HDR_PATH=$(INSTALL_ROOT_HDR)/io-pkt
PUBLIC_HDR_PATH=$(QNX_TARGET)/usr/include/io-pkt

# Check for staging area first
#EXTRA_INCVPATH+= $(HDR_PATH) $(HDR_PATH)/sys-nto
# Use headers installed in system if staging area not available
EXTRA_INCVPATH += $(PUBLIC_HDR_PATH) $(PUBLIC_HDR_PATH)/sys-nto

CCFLAGS += -D_KERNEL

# gcc sometime after 2.95.3 added a builtin log()
CCFLAGS += -Vgcc_ntoarmv7 -EL -shared -fno-builtin-log -D_QNX_ -fPIC

#################################################################################
######**********TESTING************######
# basic options (defines in DFLAGS, includes in IFLAGS)
CCFLAGS += -DSRCBASE=\"$(SRCBASE)\" -DBCMDRIVER -DBCMDONGLEHOST -DDHDTHREAD
CCFLAGS += -DUNRELEASEDCHIP -DBCMDMA32
CCFLAGS += -DBCMFILEIMAGE

# For 32 bit register accesses only
CCFLAGS += -D__REG32_ONLY__
CCFLAGS += -DBCMSDYIELD 
#CCFLAGS += -D__INCif_etherh

# Prune these
# NOT included: -DPROP_TXSTATUS
CCFLAGS += -DSOFTAP -DBDC -DTOE -DDHD_BCMEVENTS -DSHOW_EVENTS -DBCMSDIO -DBCMSDIOH_STD -DWIFI_ACT_FRAME

WL_BUILD_TIME := $(shell date +"%D %T")
CCFLAGS += -DWL_BUILD_TIME='"$(WL_BUILD_TIME)"'

CCFLAGS += -DDHD_FWCHECK
#CCFLAGS += -DBCMEMBEDIMAGE
#CCFLAGS += -DCONFIG_BCMDHD_FW_PATH='"/etc/hotspot/firmware.bin"'
CCFLAGS += -DCONFIG_BCMDHD_FW_PATH='"/etc/hotspot/rtecdc_idsup.bin"'
CCFLAGS += -DCONFIG_BCMDHD_NVRAM_PATH='"/etc/hotspot/nvram.txt"'

# options related to dbg and non-dbg targets, parsed only at the 2nd recursive iteration
ifeq ($(findstring nodebug,$(TARGET)),nodebug)
	WL_DEBUG_TYPE := Release
	CCFLAGS += -fomit-frame-pointer -O2

else
#ifeq ($(findstring debug,$(TARGET)),debug)
	WL_DEBUG_TYPE := Debug
	CCFLAGS += -O0 -g -fomit-frame-pointer -O2
	CCFLAGS	+= -DBCMINTERNAL -DBCMDBG -DBCMDBG_ERR -DDHD_DEBUG -DBCMDBG_MEM -DSDTEST -DBCMPERFSTATS
	# Add -DBCMDBG_STACK to get dynamic stack usage
	#CCFLAGS	+= -DSHOW_EVENTS -DWIFI_ACT_FRAME
#endif
endif

CCFLAGS += -DSRCBASE=\"$(SRCBASE)\" -DWL_DEBUG_TYPE='"$(WL_DEBUG_TYPE)"'

#EXTRA_INCVPATH+= $(IOPKT_ROOT)/sys $(IOPKT_ROOT)/sys/sys-nto $(IOPKT_ROOT)/lib/socket/public
#EXTRA_SRCVPATH += ../../sys ../../../shared ../../../bcmsdio/sys
#EXTRA_INCVPATH += ../../../include ../../../shared ../../sys ../../../dongle

#EXCLUDE_OBJS=bcm_app_utils.o bcmstdlib.o miniopt.o bcmsdstd_qnx.o imxsdstd.o
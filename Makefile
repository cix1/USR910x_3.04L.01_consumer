#****************************************************************************
#
#  Copyright (c) 2001, 2002, 2003, 2004  Broadcom Corporation
#  All Rights Reserved
#  No portions of this material may be reproduced in any form without the
#  written permission of:
#          Broadcom Corporation
#          16251 Laguna Canyon Road
#          Irvine, California 92618
#  All information contained in this document is Broadcom Corporation
#  company private, proprietary, and trade secret.
#
#****************************************************************************

# Top-level Makefile for all commengine xDSL platforms

include version.make

BRCM_RELEASETAG=$(BRCM_VERSION).$(BRCM_RELEASE)L.$(BRCM_EXTRAVERSION)


###########################################
#
# Define Basic Variables
#
###########################################
BUILD_DIR = $(shell pwd)
KERNEL_VER = 2.6
ifeq ($(strip $(KERNEL_VER)),2.6)
INC_KERNEL_BASE = $(BUILD_DIR)/kernel
ORIGINAL_KERNEL = linuxmips.tar.bz2
endif
KERNEL_DIR = $(INC_KERNEL_BASE)/linux
BRCMDRIVERS_DIR = $(BUILD_DIR)/bcmdrivers
USERAPPS_DIR = $(BUILD_DIR)/userapps
LINUXDIR = $(INC_KERNEL_BASE)/linux
HOSTTOOLS_DIR = $(BUILD_DIR)/hostTools
IMAGES_DIR = $(BUILD_DIR)/images
TARGETS_DIR = $(BUILD_DIR)/targets
DEFAULTCFG_DIR = $(TARGETS_DIR)/defaultcfg
XCHANGE_DIR = $(BUILD_DIR)/xChange
FSSRC_DIR = $(TARGETS_DIR)/fs.src
CFE_FILE = $(TARGETS_DIR)/cfe/cfe$(BRCM_CHIP).bin
SHARED_DIR = $(BUILD_DIR)/shared
CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
          else if [ -x /bin/bash ]; then echo /bin/bash; \
          else echo sh; fi ; fi)
GENDEFCONFIG_CMD = $(HOSTTOOLS_DIR)/scripts/gendefconfig
RUN_NOISE=0



###########################################
#
# Import Build Profiles
#
###########################################
BRCM_BOARD=bcm963xx
LAST_PROFILE=$(shell find targets -name vmlinux | sed -e "s?targets/??" -e "s?/.*??" -e "q")
ifeq ($(strip $(PROFILE)),)
PROFILE=$(LAST_PROFILE)
export PROFILE
endif
ifneq ($(strip $(PROFILE)),)
include $(TARGETS_DIR)/$(PROFILE)/$(PROFILE)
export BRCM_CHIP
export BRCM_FLASHPSI_SIZE
export BRCM_DRIVER_WIRELESS_PCMCIA_DATASWAP BRCM_DRIVER_WIRELESS_EBI_DMA
export BRCM_DRIVER_USB BRCM_DRIVER_ETHERNET_CONFIG
export BRCM_DEFAULTCFG
export BRCM_KERNEL_NF_FIREWALL BRCM_KERNEL_NF_MANGLE BRCM_KERNEL_NF_NAT
endif

###########################################
#
# Define Toolchain
#
###########################################
ifeq ($(strip $(BRCM_UCLIBC)),y)
NTC=1
ifeq ($(strip $(NTC)),1)
TOOLCHAIN=/opt/toolchains/uclibc-crosstools_gcc-3.4.2_uclibc-20050502
CROSS_COMPILE = $(TOOLCHAIN)/bin/mips-linux-uclibc-
else
TOOLCHAIN=/opt/toolchains/uclibc
CROSS_COMPILE = $(TOOLCHAIN)/bin/mips-uclibc-
endif
else
TOOLCHAIN=/usr/crossdev/mips
CROSS_COMPILE = $(TOOLCHAIN)/bin/mips-linux-
endif

AR              = $(CROSS_COMPILE)ar
AS              = $(CROSS_COMPILE)as
LD              = $(CROSS_COMPILE)ld
CC              = $(CROSS_COMPILE)gcc
CXX             = $(CROSS_COMPILE)g++
CPP             = $(CROSS_COMPILE)cpp
NM              = $(CROSS_COMPILE)nm
STRIP           = $(CROSS_COMPILE)strip
SSTRIP          = $(CROSS_COMPILE)sstrip
OBJCOPY         = $(CROSS_COMPILE)objcopy
OBJDUMP         = $(CROSS_COMPILE)objdump
RANLIB          = $(CROSS_COMPILE)ranlib

LIB_PATH        = $(TOOLCHAIN)/mips-linux/lib
LIBDIR          = $(TOOLCHAIN)/mips-linux/lib
LIBCDIR         = $(TOOLCHAIN)/mips-linux

###########################################
#
# Application-specific settings
#
###########################################
INSTALL_DIR = $(TARGETS_DIR)/fs.src
TARGET_FS = $(TARGETS_DIR)/$(PROFILE)/fs
PROFILE_DIR = $(TARGETS_DIR)/$(PROFILE)
PROFILE_PATH = $(TARGETS_DIR)/$(PROFILE)/$(PROFILE)
VENDOR_NAME = USR
FS_KERNEL_IMAGE_NAME = $(VENDOR_NAME)$(PROFILE)_fs_kernel
CFE_FS_KERNEL_IMAGE_NAME = $(VENDOR_NAME)$(PROFILE)_cfe_fs_kernel
FLASH_IMAGE_NAME = $(VENDOR_NAME)$(PROFILE)_flash_image_$(BRCM_BOARD_ID)
INC_BRCMDRIVER_PUB_PATH=$(BRCMDRIVERS_DIR)/opensource/include
INC_BRCMDRIVER_PRIV_PATH=$(BRCMDRIVERS_DIR)/broadcom/include
INC_BRCMBOARDPARMS_PATH=$(TARGETS_DIR)/boardparms
INC_ENDPOINT_PATH=$(BRCMDRIVERS_DIR)/broadcom/char/endpoint/bcm9$(BRCM_CHIP)/inc
#INC_ADSLDRV_PATH=$(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)
INC_ADSLDRV_PATH=$(BRCMDRIVERS_DIR)/broadcom/char/adsl/impl1
BROADCOM_CFM_DIR=$(BROADCOM_DIR)/cfm
INC_BRCMCFM_PATH=$(BROADCOM_CFM_DIR)/inc
VENDOR_COUNTRY = ALL
INC_BRCMSHARED_INC_PATH=$(SHARED_DIR)/include
INC_BRCMSHARED_SRC_PATH=$(SHARED_DIR)/src


ifeq ($(strip $(BRCM_APP_PHONE)),sip)
export VOXXXLOAD=1
export VOIPLOAD=1
export SIPLOAD=1

ifeq ($(strip $(BRCM_VODSL_CONFIG_MANAGER)),y)
	export BRCM_VODSL_CFGMGR=1
endif

BRCM_RELEASETAG := $(BRCM_RELEASETAG).sip
endif

ifeq ($(strip $(BRCM_APP_PHONE)),mgcp)
export VOXXXLOAD=1
export VOIPLOAD=1
export MGCPLOAD=1
export BRCM_VODSL_CFGMGR=0
BRCM_RELEASETAG := $(BRCM_RELEASETAG).mgcp
endif

ifeq ($(strip $(BRCM_PROFILER_ENABLED)),y)
export BRCM_PROFILER_TOOL=1
else
export BRCM_PROFILER_TOOL=0
endif

ifneq ($(strip $(BUILD_VODSL)),)
export VOXXXLOAD=1
endif

ifeq ($(strip $(BRCM_VODSL_STUNC)),y)
	export BRCM_VODSL_STUN_CLIENT=1
endif

BRCM_DSP_HAL := gw
BRCM_DSP_HAL_EXTENSION :=
XCHANGE_DSP_APP_EXTENSION :=
export XCHANGE_DSP_APP=$(BRCM_DSP_CODEC)

ifeq ($(strip $(BRCM_DSP_PCM)),y)
XCHANGE_DSP_APP := dspApp3341_tdm
BRCM_DSP_HAL_EXTENSION := _pcm
endif

ifeq ($(strip $(BRCM_DSP_PCM_G726)),y)
XCHANGE_DSP_APP := dspApp3341_tdm_g726
BRCM_DSP_HAL_EXTENSION := _pcm
endif

ifeq ($(strip $(BRCM_DSP_PCM_T38_EXT)),y)
XCHANGE_DSP_APP := dspApp3341_tdm_t38
BRCM_DSP_HAL_EXTENSION := _pcm
endif

ifeq ($(strip $(BRCM_DSP_APM_FXO_EXT)),y)
XCHANGE_DSP_APP := dspApp3341
BRCM_DSP_HAL_EXTENSION := _hybrid
XCHANGE_DSP_APP_EXTENSION := _fxo_ext
endif

#
#  Warning here, we do re-assign some of the variables defined earlier:
#  BRCM_DSP_HAL and BRCM_DSP_HAL_EXTENSION for example, in order to pickup
#  the correct board HAL application.
#
ifeq ($(strip $(BRCM_DSP_FXO)),y)
ifeq ($(strip $(BRCM_SLIC_LE9502)),y)
export XCHANGE_BUILD_APP=Bcm$(BRCM_CHIP)_Le9502FXO
BRCM_RELEASETAG := $(BRCM_RELEASETAG)._LE9502
BRCM_DSP_HAL := _Le9502FXO
BRCM_DSP_HAL_EXTENSION :=
export BRCM_SLIC_LE9502
else
ifeq ($(strip $(BRCM_SLIC_LE9500)),y)
export XCHANGE_BUILD_APP=Bcm$(BRCM_CHIP)_Le9500FXO
BRCM_RELEASETAG := $(BRCM_RELEASETAG)._LE9500
BRCM_DSP_HAL := _Le9500FXO
BRCM_DSP_HAL_EXTENSION :=
export BRCM_SLIC_LE9500
endif
endif
endif


#
# DSP codec flags definition.  To be used throughout the application (for configuration and vodsl)
#

BRCM_DSP_CODEC_DEFINES := -DXCFG_G711_SUPPORT=1

ifeq ($(strip $(BRCM_DSP_CODEC_G723)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G7231_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_CODEC_G726)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G726_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_CODEC_G729)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G729_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_CODEC_G7xx)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G7231_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_G726_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_G729_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_PCM)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G729_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_PCM_G726)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G726_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_FAX_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_PCM_T38_EXT)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G729_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_FAX_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_CODEC_T38_EXT)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G726_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_G729_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_FAX_SUPPORT=1
endif

ifeq ($(strip $(BRCM_DSP_APM_FXO_EXT)),y)
BRCM_DSP_CODEC_DEFINES += -DXCFG_G729_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_G726_SUPPORT=1
BRCM_DSP_CODEC_DEFINES += -DXCFG_FAX_SUPPORT=1
endif


#
#  Definition of the number of voice channels supported based on the specific
#  application being created.
#

ifeq ($(strip $(BRCM_DSP_APM_FXO_EXT)), y)
BRCM_DSP_CHAN_DEFINES = -DNUM_APM_VOICE_CHANNELS=2 -DNUM_TDM_VOICE_CHANNELS=0 -DNUM_FXO_CHANNELS=1
else
BRCM_DSP_CHAN_DEFINES = -DNUM_APM_VOICE_CHANNELS=0 -DNUM_TDM_VOICE_CHANNELS=0 -DNUM_FXO_CHANNELS=0
endif

export BRCM_DSP_CODEC_DEFINES
export BRCM_DSP_CHAN_DEFINES
export BRCM_DSP_FXO
export XCHANGE_BUILD_APP=Bcm$(BRCM_CHIP)$(BRCM_DSP_HAL)$(BRCM_DSP_HAL_EXTENSION)
export XCHANGE_DSP_APP_EXTENSION
export BRCM_DSP_HAL_EXTENSION
BRCM_RELEASETAG := $(BRCM_RELEASETAG).$(XCHANGE_DSP_APP)

# If no codec is selected, build G.711 load.
# Any XCHANGE_BUILD_APP directory would be OK
# because G.711 is included with all the voice DSP images.
ifneq ($(strip $(BUILD_VODSL)),)
ifeq ($(strip $(XCHANGE_DSP_APP)),)
export XCHANGE_BUILD_APP=Bcm$(BRCM_CHIP)gw
export XCHANGE_DSP_APP=g711
BRCM_RELEASETAG := $(BRCM_RELEASETAG).g711
endif
endif

ifeq ($(strip $(BRCM_MIPS_ONLY_BUILD)),y)
export XCHANGE_BUILD_APP=Bcm$(BRCM_CHIP)lv
BRCM_DSP_HAL := lv
BRCM_DSP_HAL_EXTENSION :=
XCHANGE_DSP_APP_EXTENSION=
endif

ifeq ($(strip $(BRCM_VODSL_DUAL_3341)),y)
BRCM_RELEASETAG := $(BRCM_RELEASETAG).dual3341
endif

#Set up ADSL standard
export ADSL=$(BRCM_ADSL_STANDARD)

#Set up ADSL_PHY_MODE  {file | obj}
export ADSL_PHY_MODE=file

#Set up ADSL_SELF_TEST
export ADSL_SELF_TEST=$(BRCM_ADSL_SELF_TEST)

###########################################
#
# Complete list of applications
#
###########################################
export OPENSOURCE_DIR=$(USERAPPS_DIR)/opensource
SUBDIRS_OPENSOURCE = $(OPENSOURCE_DIR)/atm2684/pvc2684ctl \
        $(OPENSOURCE_DIR)/openssl \
        $(OPENSOURCE_DIR)/ipsec-tools \
        $(OPENSOURCE_DIR)/bridge-utils \
        $(OPENSOURCE_DIR)/ppp/pppoe \
        $(OPENSOURCE_DIR)/udhcp \
        $(OPENSOURCE_DIR)/iptables \
        $(OPENSOURCE_DIR)/ebtables \
        $(OPENSOURCE_DIR)/reaim  \
        $(OPENSOURCE_DIR)/iproute2  \
        $(OPENSOURCE_DIR)/libosip2 \
        $(OPENSOURCE_DIR)/siproxd \
        $(OPENSOURCE_DIR)/zebra  \
        $(OPENSOURCE_DIR)/net-snmp  \
        $(OPENSOURCE_DIR)/ftpd \
        $(OPENSOURCE_DIR)/libcreduction \
        $(OPENSOURCE_DIR)/busybox

#In future, we need to add soap when it
#is decoupled from cli

export BROADCOM_DIR=$(USERAPPS_DIR)/broadcom
SUBDIRS_BROADCOM = $(BROADCOM_DIR)/nvram \
	$(BROADCOM_DIR)/cfm \
        $(BROADCOM_DIR)/upnp/router/upnp \
        $(BROADCOM_DIR)/nas \
        $(BROADCOM_DIR)/wlctl \
        $(BROADCOM_DIR)/vodsl \
        $(BROADCOM_DIR)/atmctl \
        $(BROADCOM_DIR)/adslctl \
        $(BROADCOM_DIR)/netctl \
        $(BROADCOM_DIR)/dnsprobe \
        $(BROADCOM_DIR)/igmp \
        $(BROADCOM_DIR)/dhcpr \
	$(BROADCOM_DIR)/sntp \
	$(BROADCOM_DIR)/ippd \
	$(BROADCOM_DIR)/ddnsd \
	$(BROADCOM_DIR)/ethctl \
        $(BROADCOM_DIR)/hotplug \
        $(BROADCOM_DIR)/epittcp \
        $(BROADCOM_DIR)/snmp \
        $(BROADCOM_DIR)/tr69c \
        $(BROADCOM_DIR)/ses

SUBDIRS_APP = $(SUBDIRS_BROADCOM) $(SUBDIRS_OPENSOURCE)
SUBDIRS = $(foreach dir, $(SUBDIRS_APP), $(shell if [ -d "$(dir)" ]; then echo $(dir); fi))

OPENSOURCE_APPS = ipsec-tools pvc2684ctl pvc2684d brctl pppd udhcp iptables ebtables \
                  reaim tc libosip2 siproxd snmp zebra bftpd busybox 

BROADCOM_APPS = nvram cfm upnp nas wlctl vodsl atmctl adslctl netctl dnsprobe \
                igmp dhcpr diagapp sntp ddnsd ilmi ippd hotplug ethctl epittcp snmp ses
LIBC_OPTIMIZATION = libcreduction

ifneq ($(strip $(BUILD_GDBSERVER)),)
TOOLCHAIN_UTIL_APPS = gdbserver
endif

BUSYBOX_DIR = $(OPENSOURCE_DIR)/busybox

BRCMAPPS = openssl $(BROADCOM_APPS) $(OPENSOURCE_APPS) $(TOOLCHAIN_UTIL_APPS) $(LIBC_OPTIMIZATION)

all: sanity_check profile_check kernelbuild modbuild app hosttools buildimage

menuconfig:
	@cd $(INC_KERNEL_BASE); \
	if [ ! -e linux/CREDITS ]; then \
	  echo Untarring original Linux kernel source...; \
	  (tar xkfj $(ORIGINAL_KERNEL) 2> /dev/null || true); \
	fi
	$(MAKE) -C $(KERNEL_DIR)/scripts/lxdialog HOSTCC=gcc
	$(CONFIG_SHELL) $(HOSTTOOLS_DIR)/scripts/Menuconfig $(TARGETS_DIR)/config.in

sanity_check:
	@if [ "$(PROFILE)" = "" ]; then \
          echo You need to specify build profile name from $(TARGETS_DIR) using 'make PROFILE=<profile name>...'; exit 1; \
	fi

profile_check:
	@if [ "$(LAST_PROFILE)" != "" ] && [ "$(LAST_PROFILE)" != "$(PROFILE)" ]; then \
		echo "The specified profile, $(PROFILE), differs from the last one built, $(LAST_PROFILE)."; \
		echo "The entire image must be rebuilt."; \
		read -p "Press ENTER to rebuild the entire image or CTRL-C to abort. " ; \
		$(MAKE) PROFILE=$(LAST_PROFILE) clean; \
		$(MAKE) PROFILE=$(PROFILE); \
		echo "Ignore the make exit error, Error 1"; \
		exit 1; \
	fi

$(KERNEL_DIR)/vmlinux:
	$(GENDEFCONFIG_CMD) $(PROFILE_PATH)
	cd $(KERNEL_DIR); \
	cp -f $(KERNEL_DIR)/arch/mips/defconfig $(KERNEL_DIR)/.config; \
	$(MAKE) oldconfig; $(MAKE); $(MAKE) modules_install

kernelbuild:
ifeq ($(wildcard $(KERNEL_DIR)/vmlinux),)
	@cd $(INC_KERNEL_BASE); \
	if [ ! -e linux/CREDITS ]; then \
	  echo Untarring original Linux kernel source...; \
	  (tar xkfj $(ORIGINAL_KERNEL) 2> /dev/null || true); \
	fi
	$(GENDEFCONFIG_CMD) $(PROFILE_PATH)
	cd $(KERNEL_DIR); \
	cp -f $(KERNEL_DIR)/arch/mips/defconfig $(KERNEL_DIR)/.config; \
	$(MAKE) oldconfig; $(MAKE)
else
	cd $(KERNEL_DIR); $(MAKE)
endif

kernel: profile_check kernelbuild hosttools buildimage

ifeq ($(strip $(VOXXXLOAD)),1)
modbuild: touch_voice_files
	cd $(KERNEL_DIR); $(MAKE) modules && $(MAKE) modules_install
else
modbuild:
	cd $(KERNEL_DIR); $(MAKE) modules && $(MAKE) modules_install
endif

modules: profile_check modbuild hosttools buildimage

app: profile_check prebuild $(BRCMAPPS) hosttools rm_cvs buildimage 

prebuild:
	mkdir -p $(INSTALL_DIR)/bin $(INSTALL_DIR)/lib

rm_cvs:
	@echo "Removing CVS info"
	find $(INSTALL_DIR) -name 'CVS' -print -exec rm -rf "{}" ";"

# touch_voice_files doesn't clean up voice, just enables incremental build of voice code
touch_voice_files:
	find bcmdrivers/broadcom/char/endpoint/ \( -name '*.o' -o -name '*.a' -o -name '*.lib' -o -name '*.ko' -o -name '*.cmd' -o -name '.*.cmd' -o -name '*.c' -o -name '*.mod' \) -print -exec rm -f "{}" ";"
	rm -rf kernel/linux/.tmp_versions/endpointdd.mod
	rm -rf kernel/linux/arch/mips/defconfig
	rm -rf kernel/linux/include/config/bcm/endpoint/
	rm -rf kernel/linux/include/asm-mips/offset.h
	rm -rf kernel/linux/include/asm-mips/reg.h
	find kernel/linux/lib/ -name '*.o' -print -exec rm -f "{}" ";"
	find kernel/linux/lib/ -name '*.lib' -print -exec rm -f "{}" ";"

# Build user applications depending on if they are
# specified in the profile
ifneq ($(strip $(BUILD_PVC2684CTL)),)
export BUILD_PVC2684D=$(BUILD_PVC2684CTL)
pvc2684d:
pvc2684ctl:
	$(MAKE) -C $(OPENSOURCE_DIR)/atm2684/pvc2684ctl $(BUILD_PVC2684CTL)
else
pvc2684ctl:
endif

ifneq ($(strip $(BUILD_BRCTL)),)
brctl:
	cd $(OPENSOURCE_DIR);   (tar xkfj bridge-utils.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/bridge-utils $(BUILD_BRCTL)
else
brctl:
endif

ifneq ($(strip $(BUILD_VCONFIG)),)
export BUILD_VCONFIG=y
endif

ifneq ($(strip $(BUILD_CFM)),)

ifneq ($(strip $(BUILD_CFM_MENU)),)
export BUILD_CFM_MENU=y
endif

cfm:
	$(MAKE) -C $(BROADCOM_DIR)/cfm $(BUILD_CFM)
else
cfm:
endif

# iptables is dependent on kernel netfilter modules
ifneq ($(strip $(BRCM_KERNEL_NETFILTER)),)
ifneq ($(strip $(BUILD_IPTABLES)),)
iptables:
	cd $(OPENSOURCE_DIR);   (tar xkfj iptables.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/iptables $(BUILD_IPTABLES)
iptables-build:
	cd $(OPENSOURCE_DIR);   (tar xkfj iptables.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/iptables static
else
iptables:
endif
else
iptables:
	@echo Warning: You need to enable netfilter in the kernel !!!!!
endif

ifneq ($(strip $(BUILD_EBTABLES)),)
ebtables:
	cd $(OPENSOURCE_DIR);   (tar xkfj ebtables.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/ebtables $(BUILD_EBTABLES)
else
ebtables:
endif

ifneq ($(strip $(BUILD_PPPD)),)
pppd:
	$(MAKE) -C $(OPENSOURCE_DIR)/ppp/pppoe $(BUILD_PPPD)
else
pppd:
endif

ifneq ($(strip $(BUILD_REAIM)),)
reaim:
	cd $(OPENSOURCE_DIR);   (tar xkfj reaim.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/reaim $(BUILD_REAIM)
else
reaim:
endif

ifneq ($(strip $(BRCM_KERNEL_NETQOS)),)
tc:
	cd $(OPENSOURCE_DIR);   (tar xkfj iproute2.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/iproute2 dynamic
else
tc:
endif

ifneq ($(strip $(BUILD_GDBSERVER)),)
gdbserver:
	install -m 755 $(TOOLCHAIN)/mips-linux-uclibc/target-apps/usr/bin/gdbserver $(INSTALL_DIR)/bin
	$(STRIP) $(INSTALL_DIR)/bin/gdbserver
else
gdbserver:
endif

ifneq ($(strip $(BUILD_ETHWAN)),)
export BUILD_ETHWAN=y
endif

ifneq ($(strip $(BUILD_UDHCP)),)
udhcp:
	$(MAKE) -C $(OPENSOURCE_DIR)/udhcp $(BUILD_UDHCP)
else
udhcp:
endif

# UPNP is dependent on iptables
ifneq ($(strip $(BUILD_IPTABLES)),)
ifneq ($(strip $(BUILD_UPNP)),)
upnp: iptables-build
	$(MAKE) -C $(BROADCOM_DIR)/upnp/router/upnp  $(BUILD_UPNP)
else
upnp:
endif
else
upnp:
	@echo Warning: You need to build iptables first !!!!!
endif

ifneq ($(strip $(BUILD_IPSEC_TOOLS)),)
ipsec-tools:
	cd $(OPENSOURCE_DIR);   (tar xkfj ipsec-tools.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/ipsec-tools $(BUILD_IPSEC_TOOLS)
else
ipsec-tools:
endif

ifneq ($(strip $(BUILD_CERT)),)
openssl:
	cd $(OPENSOURCE_DIR);   (tar xkfj openssl.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/openssl dynamic
else
openssl:
endif


ifneq ($(strip $(BUILD_SIPROXD)),)
siproxd:
	cd $(OPENSOURCE_DIR);   (tar xkfj siproxd.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/siproxd $(BUILD_SIPROXD)
libosip2:
	cd $(OPENSOURCE_DIR);   (tar xkfj libosip2.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/libosip2
else
siproxd:

libosip2:

endif

ifneq ($(strip $(BUILD_SNMP)),)

ifneq ($(strip $(BUILD_SNMP_SET)),)
export BUILD_SNMP_SET=1
else
export BUILD_SNMP_SET=0
endif

ifneq ($(strip $(BUILD_SNMP_ADSL_MIB)),)
export BUILD_SNMP_ADSL_MIB=1
else
export BUILD_SNMP_ADSL_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_ATM_MIB)),)
export BUILD_SNMP_ATM_MIB=1
else
export BUILD_SNMP_ATM_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_AT_MIB)),)
export BUILD_SNMP_AT_MIB=1
else
export BUILD_SNMP_AT_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_SYSOR_MIB)),)
export BUILD_SNMP_SYSOR_MIB=1
else
export BUILD_SNMP_SYSOR_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_TCP_MIB)),)
export BUILD_SNMP_TCP_MIB=1
else
export BUILD_SNMP_TCP_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_UDP_MIB)),)
export BUILD_SNMP_UDP_MIB=1
else
export BUILD_SNMP_UDP_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_IP_MIB)),)
export BUILD_SNMP_IP_MIB=1
else
export BUILD_SNMP_IP_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_ICMP_MIB)),)
export BUILD_SNMP_ICMP_MIB=1
else
export BUILD_SNMP_ICMP_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_SNMP_MIB)),)
export BUILD_SNMP_SNMP_MIB=1
else
export BUILD_SNMP_SNMP_MIB=0
endif

ifneq ($(strip $(BUILD_SNMP_ATMFORUM_MIB)),)
export BUILD_SNMP_ATMFORUM_MIB=1
else
export BUILD_SNMP_ATMFORUM_MIB=0
endif

ifneq ($(strip $(BRCM_SNMP)),)

ifneq ($(strip $(BUILD_SNMP_CHINA_TELECOM_CPE_MIB)),)
export BUILD_SNMP_CHINA_TELECOM_CPE_MIB=y
export BUILD_SNMP_MIB2=y
endif

ifneq ($(strip $(BUILD_SNMP_UDP)),)
export BUILD_SNMP_UDP=y
endif

ifneq ($(strip $(BUILD_SNMP_EOC)),)
export BUILD_SNMP_EOC=y
endif

ifneq ($(strip $(BUILD_SNMP_AAL5)),)
export BUILD_SNMP_AAL5=y
endif

ifneq ($(strip $(BUILD_SNMP_AUTO)),)
export BUILD_SNMP_AUTO=y
endif

ifneq ($(strip $(BUILD_SNMP_DEBUG)),)
export BUILD_SNMP_DEBUG=y
endif

ifneq ($(strip $(BUILD_SNMP_TRANSPORT_DEBUG)),)
export BUILD_SNMP_TRANSPORT_DEBUG=y
endif

ifneq ($(strip $(BUILD_SNMP_LAYER_DEBUG)),)
export BUILD_SNMP_LAYER_DEBUG=y
endif
endif

snmp:
ifneq ($(strip $(BRCM_SNMP)),)
##	$(MAKE) -C $(BROADCOM_DIR)/snmp $(BUILD_SNMP)
else
	cd $(OPENSOURCE_DIR);   (tar xkfj net-snmp.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/net-snmp $(BUILD_SNMP)
endif
else
snmp:
endif

ifneq ($(strip $(BUILD_ILMI)),)
ilmi:
	cd $(OPENSOURCE_DIR);   (tar xkfj net-snmp.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(BROADCOM_DIR)/ilmi $(BUILD_ILMI)
else
ilmi:
endif

ifneq ($(strip $(BUILD_VODSL)),)
vodsl:
	$(MAKE) -C $(BROADCOM_DIR)/vodsl $(BUILD_VODSL)
else
vodsl:
endif

# Leave it for the future when soap server is decoupled from cfm
ifneq ($(strip $(BUILD_SOAP)),)
ifeq ($(strip $(BUILD_SOAP_VER)),2)
soapserver:
	$(MAKE) -C $(BROADCOM_DIR)/SoapToolkit/SoapServer $(BUILD_SOAP)
else
soap:
	$(MAKE) -C $(BROADCOM_DIR)/soap $(BUILD_SOAP)
endif
else
soap:
endif

ifneq ($(strip $(BUILD_NAS)),)
export WIRELESS=1
nas:
	$(MAKE) -C $(BROADCOM_DIR)/nas $(BUILD_NAS)

#add hotplug here, for nas use only
hotplug:
	$(MAKE) -C $(BROADCOM_DIR)/hotplug $(BUILD_NAS)

else
export WIRELESS=0
nas:
#add hotplug here, for nas use only
hotplug:
endif

ifneq ($(strip $(BUILD_WLCTL)),)
export WIRELESS=1
wlctl:
	$(MAKE) -C $(BROADCOM_DIR)/wlctl $(BUILD_WLCTL)
else
export WIRELESS=0
wlctl:
endif

#Always compile Ethernet control utility
ethctl:
	$(MAKE) -C $(BROADCOM_DIR)/ethctl dynamic

ifneq ($(strip $(BUILD_DNSPROBE)),)
dnsprobe:
	$(MAKE) -C $(BROADCOM_DIR)/dnsprobe $(BUILD_DNSPROBE)
else
dnsprobe:
endif

ifneq ($(strip $(BUILD_IGMP)),)
igmp:
	$(MAKE) -C $(BROADCOM_DIR)/igmp $(BUILD_IGMP)
else
igmp:
endif

ifneq ($(strip $(BUILD_DHCPR)),)
dhcpr:
	$(MAKE) -C $(BROADCOM_DIR)/dhcpr $(BUILD_DHCPR)
else
dhcpr:
endif

ifneq ($(strip $(BUILD_ZEBRA)),)
zebra:
	cd $(OPENSOURCE_DIR);   (tar xkfj zebra.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/zebra $(BUILD_ZEBRA)
else
zebra:
endif

ifneq ($(strip $(BUILD_ATMCTL)),)
atmctl:
	$(MAKE) -C $(BROADCOM_DIR)/atmctl $(BUILD_ATMCTL)
else
atmctl:
endif

ifneq ($(strip $(BUILD_ADSLCTL)),)
adslctl:
	$(MAKE) -C $(BROADCOM_DIR)/adslctl $(BUILD_ADSLCTL)
else
adslctl:
endif

ifeq ($(strip $(BUILD_CFM_CLI)),y)
ifneq ($(strip $(BUILD_NETCTL)),)
netctl:
	$(MAKE) -C $(BROADCOM_DIR)/netctl $(BUILD_NETCTL)
else
netctl:
endif
else
netctl:
endif

ifneq ($(strip $(BUILD_BUSYBOX)),)
busybox:
	cd $(OPENSOURCE_DIR); (tar xkfj busybox.tar.bz2 2> /dev/null || true)
#	$(MAKE) -C $(OPENSOURCE_DIR)/busybox $(BUILD_BUSYBOX)
	cd $(OPENSOURCE_DIR)/busybox; cp -f brcm.config .config
	$(MAKE) -C $(OPENSOURCE_DIR)/busybox install
else
busybox:
endif

ifneq ($(strip $(BUILD_LIBCREDUCTION)),)
libcreduction:
	mkdir -p $(OPENSOURCE_DIR)/libcreduction/uclibc
	$(MAKE) -C $(OPENSOURCE_DIR)/libcreduction install
else
libcreduction:
endif

ifneq ($(strip $(BUILD_DIAGAPP)),)
diagapp:
	$(MAKE) -C $(BROADCOM_DIR)/diagapp $(BUILD_DIAGAPP)
else
diagapp:
endif

ifneq ($(strip $(BUILD_FTPD)),)
bftpd:
	cd $(OPENSOURCE_DIR);   (tar xkfj ftpd.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/ftpd $(BUILD_FTPD)
else
bftpd:
endif

ifneq ($(strip $(BUILD_DDNSD)),)
ddnsd:
	$(MAKE) -C $(BROADCOM_DIR)/ddnsd $(BUILD_DDNSD)
else
ddnsd:
endif

ifneq ($(strip $(BUILD_SNTP)),)
sntp:
	$(MAKE) -C $(BROADCOM_DIR)/sntp $(BUILD_SNTP)
else
sntp:
endif

ifneq ($(strip $(BUILD_EPITTCP)),)
epittcp:
	$(MAKE) -C $(BROADCOM_DIR)/epittcp $(BUILD_EPITTCP)
else
epittcp:
endif

ifneq ($(strip $(BUILD_SES)),)
ses:
	$(MAKE) -C $(BROADCOM_DIR)/ses $(BUILD_SES)
else
ses:
endif

ifneq ($(strip $(BUILD_NVRAM)),)
nvram:
	$(MAKE) -C $(BROADCOM_DIR)/nvram $(BUILD_NVRAM)
else
nvram:
endif

ifneq ($(strip $(BUILD_IPPD)),)
ippd:
	$(MAKE) -C $(BROADCOM_DIR)/ippd $(BUILD_IPPD)
else
ippd:
endif

ifneq ($(strip $(BUILD_PORT_MIRRORING)),)
export BUILD_PORT_MIRRORING=1
else
export BUILD_PORT_MIRRORING=0
endif

hosttools:
	$(MAKE) -C $(HOSTTOOLS_DIR)


buildimage: $(KERNEL_DIR)/vmlinux
	su --command="cd $(TARGETS_DIR); ./buildFS"
ifeq ($(strip $(BRCM_KERNEL_ROOTFS)),squashfs)
	#$(HOSTTOOLS_DIR)/mksquashfs $(TARGET_FS) $(PROFILE_DIR)/rootfs.img -noappend -be -always-use-fragments -gzip
	$(HOSTTOOLS_DIR)/mksquashfs $(TARGET_FS) $(PROFILE_DIR)/rootfs.img -noappend -be -lzma -no-fragments -noI
else
 ifeq ($(strip $(BRCM_KERNEL_ROOTFS)),cramfs)
#	$(HOSTTOOLS_DIR)/mkcramfs -r -g $(TARGET_FS) $(PROFILE_DIR)/rootfs.img
	$(HOSTTOOLS_DIR)/mkcramfs -r $(TARGET_FS) $(PROFILE_DIR)/rootfs.img
 else
  ifeq ($(strip $(BRCM_KERNEL_ROOTFS)),jffs2)
	$(HOSTTOOLS_DIR)/mkfs.jffs2 -b -p -e $(BRCM_FLASHBLK_SIZE) -r $(TARGET_FS) -o $(PROFILE_DIR)/rootfs.img
  endif
 endif
endif

ifneq ($(strip $(BRCM_KERNEL_ROOTFS)),nfs)
	cd $(PROFILE_DIR); \
	cp $(KERNEL_DIR)/vmlinux . ; \
	$(STRIP) --remove-section=.note --remove-section=.comment vmlinux; \
	$(OBJCOPY) -O binary vmlinux vmlinux.bin; \
	$(HOSTTOOLS_DIR)/cmplzma -k -2 vmlinux vmlinux.bin vmlinux.lz;\
	$(HOSTTOOLS_DIR)/bcmImageBuilder --output $(FS_KERNEL_IMAGE_NAME) --chip $(BRCM_CHIP) --board $(BRCM_BOARD_ID) --blocksize $(BRCM_FLASHBLK_SIZE) --cfefile $(CFE_FILE) --rootfsfile rootfs.img --kernelfile vmlinux.lz; \
	$(HOSTTOOLS_DIR)/bcmImageBuilder --output $(CFE_FS_KERNEL_IMAGE_NAME) --chip $(BRCM_CHIP) --board $(BRCM_BOARD_ID) --blocksize $(BRCM_FLASHBLK_SIZE) --cfefile $(CFE_FILE) --rootfsfile rootfs.img --kernelfile vmlinux.lz --include-cfe; \
	$(HOSTTOOLS_DIR)/createimg -b $(BRCM_BOARD_ID) -n $(BRCM_NUM_MAC_ADDRESSES) -m $(BRCM_BASE_MAC_ADDRESS) -i $(CFE_FS_KERNEL_IMAGE_NAME) -o $(FLASH_IMAGE_NAME) -l $(VENDOR_COUNTRY); \
	$(HOSTTOOLS_DIR)/addvtoken $(FLASH_IMAGE_NAME) $(FLASH_IMAGE_NAME).w
	@mkdir -p $(IMAGES_DIR)
	@cp $(PROFILE_DIR)/$(FS_KERNEL_IMAGE_NAME) $(IMAGES_DIR)/$(FS_KERNEL_IMAGE_NAME)_$(BRCM_RELEASETAG)-$(shell date '+%y%m%d_%H%M')
	@echo
	@echo -e "Done! Image $(PROFILE) has been built in $(IMAGES_DIR)."
else
	cd $(PROFILE_DIR); \
	cp $(KERNEL_DIR)/vmlinux . ; \
	$(STRIP) --remove-section=.note --remove-section=.comment vmlinux
	@echo
	@echo -e "\t=== Following the below steps to start your NFS root file system on host ==="
	@echo -e "Step 1: Copy $(PROFILE_DIR)/vmlinux to your TFTP server boot directory, such as /tftpboot"
	@echo -e "Step 2: Add \"$(PROFILE_DIR)/fs *(rw,no_root_squash)\" to /etc/exports"
	@echo -e "Step 3: Become root and restart your nfs server, such as \"service nfs restart\""
	@echo -e "Step 4: Reboot your board and break into CFE bootloader, choose h on \"Run from flash/host\" and vmlinux on \"Default host run file name\""
endif


###########################################
#
# System code clean-up
#
###########################################

subdirs: $(patsubst %, _dir_%, $(SUBDIRS))

$(patsubst %, _dir_%, $(SUBDIRS)) :
	$(MAKE) -C $(patsubst _dir_%, %, $@) $(TGT)

clean: target_clean app_clean kernel_clean hosttools_clean
	rm -f .tmpconfig*

fssrc_clean:
	rm -fr $(INSTALL_DIR)/bin
	rm -fr $(INSTALL_DIR)/sbin
	rm -fr $(INSTALL_DIR)/lib
	rm -fr $(INSTALL_DIR)/upnp
	rm -fr $(INSTALL_DIR)/docs
	rm -fr $(INSTALL_DIR)/webs
	rm -fr $(INSTALL_DIR)/usr
	rm -fr $(INSTALL_DIR)/linuxrc

kernel_clean: sanity_check
	$(MAKE) -C $(KERNEL_DIR) mrproper
	rm -f $(KERNEL_DIR)/arch/mips/defconfig
	rm -f $(HOSTTOOLS_DIR)/lzma/decompress/*.o
	rm -rf $(XCHANGE_DIR)/dslx/lib/LinuxKernel
	rm -rf $(XCHANGE_DIR)/dslx/obj/LinuxKernel

app_clean: sanity_check fssrc_clean
	$(MAKE) subdirs TGT=clean
	rm -rf $(XCHANGE_DIR)/dslx/lib/LinuxUser
	rm -rf $(XCHANGE_DIR)/dslx/obj/LinuxUser

target_clean: sanity_check
	rm -f $(PROFILE_DIR)/rootfs.img
	rm -f $(PROFILE_DIR)/vmlinux
	rm -f $(PROFILE_DIR)/vmlinux.bin
	rm -f $(PROFILE_DIR)/vmlinux.lz
	rm -f $(PROFILE_DIR)/$(FS_KERNEL_IMAGE_NAME)
	rm -f $(PROFILE_DIR)/$(CFE_FS_KERNEL_IMAGE_NAME)
	rm -f $(PROFILE_DIR)/$(FLASH_IMAGE_NAME)
	rm -f $(PROFILE_DIR)/$(FLASH_IMAGE_NAME).w
	rm -fr $(PROFILE_DIR)/modules
	find targets -name vmlinux -print -exec rm -f "{}" ";"
	su --command="rm -fr $(TARGET_FS)"

hosttools_clean:
	$(MAKE) -C $(HOSTTOOLS_DIR) clean

###########################################
#
# System-wide exported variables
# (in alphabetical order)
#
###########################################

export \
AR                         \
AS                         \
BRCM_APP_PHONE             \
BRCMAPPS                   \
BRCM_BOARD                 \
BRCM_DRIVER_PCI            \
BRCMDRIVERS_DIR            \
BRCM_DSP_APM_FXO           \
BRCM_DSP_APM_FXO_EXT       \
BRCM_DSP_CODEC_G711        \
BRCM_DSP_CODEC_G723        \
BRCM_DSP_CODEC_G726        \
BRCM_DSP_CODEC_G729        \
BRCM_DSP_CODEC_G7xx        \
BRCM_DSP_CODEC_T38_EXT     \
BRCM_DSP_CODEC_T38_INT     \
BRCM_DSP_HAL               \
BRCM_DSP_HAL_EXTENSION     \
BRCM_DSP_PCM               \
BRCM_DSP_PCM_G726          \
BRCM_DSP_PCM_T38_EXT       \
BRCM_EXTRAVERSION          \
BRCM_KERNEL_NETQOS         \
BRCM_KERNEL_ROOTFS         \
BRCM_LDX_APP               \
BRCM_MIPS_ONLY_BUILD       \
BRCM_MIPS_ONLY_BUILD       \
BRCM_PSI_VERSION           \
BRCM_PTHREADS              \
BRCM_RELEASE               \
BRCM_RELEASETAG            \
BRCM_SNMP                  \
BRCM_UCLIBC                \
BRCM_VERSION               \
BRCM_VODSL_DUAL_3341       \
BRCM_VOICE_COUNTRY_JAPAN   \
BRCM_VOICE_GLOBAL_CFLAGS   \
BROADCOM_CFM_DIR           \
BUILD_ADSLCTL              \
BUILD_ATMCTL               \
BUILD_BR2684CTL            \
BUILD_BRCM_VLAN            \
BUILD_BRCTL                \
BUILD_BUSYBOX              \
BUILD_CERT                 \
BUILD_CFM                  \
BUILD_CFM_CLI              \
BUILD_CFM_SSHD             \
BUILD_CFM_TELNETD          \
BUILD_DDNSD                \
BUILD_DHCPR                \
BUILD_DIAGAPP              \
BUILD_DIR                  \
BUILD_DNSPROBE             \
BUILD_EBTABLES             \
BUILD_EPITTCP              \
BUILD_ETHWAN               \
BUILD_FTPD                 \
BUILD_GDBSERVER            \
BUILD_IGMP                 \
BUILD_IPPD                 \
BUILD_IPSEC_TOOLS          \
BUILD_IPTABLES             \
BUILD_NAS                  \
BUILD_NETCTL               \
BUILD_NVRAM                \
BUILD_PORT_MIRRORING			 \
BUILD_PPPD                 \
BUILD_PVC2684CTL           \
BUILD_REAIM                \
BUILD_RT2684D              \
BUILD_SES                  \
BUILD_SIPROXD              \
BUILD_SLACTEST             \
BUILD_SNMP                 \
BUILD_SNTP                 \
BUILD_SOAP                 \
BUILD_SOAP_VER             \
BUILD_SSHD_MIPS_GENKEY     \
BUILD_TOD                  \
BUILD_TR69C                \
BUILD_TR69C_SSL            \
BUILD_UDHCP                \
BUILD_UPNP                 \
BUILD_VCONFIG              \
BUILD_VCONFIG              \
BUILD_VODSL                \
BUILD_WLCTL                \
BUILD_ZEBRA                \
BUSYBOX_DIR                \
CC                         \
CROSS_COMPILE              \
CXX                        \
DEFAULTCFG_DIR             \
FSSRC_DIR                  \
HOSTTOOLS_DIR              \
INC_ADSLDRV_PATH           \
INC_BRCMBOARDPARMS_PATH    \
INC_BRCMCFM_PATH           \
INC_BRCMDRIVER_PRIV_PATH   \
INC_BRCMDRIVER_PUB_PATH    \
INC_BRCMSHARED_INC_PATH    \
INC_BRCMSHARED_SRC_PATH    \
INC_ENDPOINT_PATH          \
INC_KERNEL_BASE            \
INSTALL_DIR                \
JTAG_KERNEL_DEBUG          \
KERNEL_DIR                 \
LD                         \
LIBCDIR                    \
LIBDIR                     \
LIB_PATH                   \
LINUXDIR                   \
NM                         \
OBJCOPY                    \
OBJDUMP                    \
PROFILE_DIR                \
RANLIB                     \
RUN_NOISE                  \
SSTRIP                     \
STRIP                      \
TARGETS_DIR                \
TOOLCHAIN                  \
USERAPPS_DIR               \
WEB_POPUP                  \
XCHANGE_DIR                \
XCHANGE_DSP_APP_EXTENSION


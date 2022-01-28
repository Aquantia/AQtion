# SPDX-License-Identifier: GPL-2.0-only
################################################################################
#
# Atlantic Network Driver
#
# Copyright (C) 2014-2019 aQuantia Corporation
# Copyright (C) 2019-2020 Marvell International Ltd.
#
################################################################################

#
# Makefile for the AQtion(tm) Ethernet driver
#

ifneq ($(KERNELRELEASE),)
include $(src)/Kbuild
else


TARGET := atlantic

export DEBIAN=`/usr/bin/dpkg --search /usr/bin/dpkg >/dev/null 2>&1 && echo 1 || echo 0`

export KO_EXISTS=`cat /etc/modules 2>/dev/null | grep atlantic && echo 1 || echo 0`

ifndef KDIR
	BUILD_DIR:=/lib/modules/$(shell uname -r)/build
else
	BUILD_DIR:=$(KDIR)
endif

PWD:=$(shell pwd)


all:
	$(MAKE) -j4 -C $(BUILD_DIR) M="$(PWD)" modules

dox:	.doxygen
	@doxygen $<

clean:
	$(MAKE) -j4 -C $(BUILD_DIR) M="$(PWD)" clean
	@-rm -rdf doc/html 2 > /dev/null

load:
	modprobe ptp
	modprobe crc_itu_t
	modprobe -q macsec || true
	insmod ./$(TARGET).ko

unload:
	rmmod ./$(TARGET).ko

install:
	@install -D -m 644 ${TARGET}.ko /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/aquantia/atlantic/${TARGET}.ko
	@depmod -a $(shell uname -r)
	@$(MAKE) -f $(lastword $(MAKEFILE_LIST)) updateramfs

updateramfs:
	@if [ "${DEBIAN}" = "1" ]; then \
		lsinitramfs /boot/initrd.img-$(shell uname -r)|grep ${TARGET}.ko >/dev/null 2>&1 ; \
		export grep_result=$$? ;\
	else \
		lsinitrd|grep ${TARGET}.ko >/dev/null 2>&1 ; \
		export grep_result=$$? ;\
	fi ; \
	if [ $$grep_result -eq 0 ]; then \
		export inramfs=1 ; \
	else \
		export inramfs=0 ; \
	fi ; \
	if [ $$inramfs -eq 1 ]; then \
		echo "${TARGET}.ko is in initramfs." ; \
		echo "CAUTION! Updating initramfs is potentially dangerous." ; \
		echo -n "Attempt initramfs update? [yN] " ; \
		read yn ; \
		case $$yn in \
			[Yy]) export updateramfs=1; break;; \
			*) export updateramfs=0; break;; \
		esac ; \
	else \
		export updateramfs=1 ; \
	fi ; \
	if [ $$updateramfs -eq 1 -a "${DEBIAN}" = "1" ]; then \
		update-initramfs -u ; \
		if [ "${KO_EXISTS}" = "0" ]; then echo atlantic >> /etc/modules ; fi; \
	elif [ $$updateramfs -eq 1 ]; then \
		dracut --force ; \
	fi

uninstall:
	@modprobe -r -n --first-time ${TARGET} >/dev/null 2>&1 ; \
	if [ $$? -eq 0 ]; then \
		echo -n "The driver is in use. Uninstall will stop the traffic! Continue? [yN] " ; \
		read yn ; \
		case $$yn in \
			[Yy]) export yn_y=1; break;; \
			*) export yn_n=0; break;; \
		esac ; \
		if [ ! $$yn_y ]; then \
			echo "Uninstall aborted." ; \
			exit 1 ; \
		fi \
	fi
	@modprobe -r ${TARGET}
	@if [ "${KO_EXISTS}" != "0" ]; then sed -in '/${TARGET}/d' /etc/modules ; fi
	@rm -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/aquantia/atlantic/${TARGET}.ko
	@depmod -a $(shell uname -r)
	@$(MAKE) -f $(lastword $(MAKEFILE_LIST)) updateramfs


endif

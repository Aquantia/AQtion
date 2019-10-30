################################################################################
#
# aQuantia Ethernet Controller AQtion Linux Driver
# Copyright(c) 2014-2019 aQuantia Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information: <rdc-drv@aquantia.com>
# aQuantia Corporation, 91 E. Tasman Dr. Suite 100, San Jose, CA 95134, USA
#
################################################################################

#
# Makefile for the AQtion(tm) Ethernet driver
#


TARGET := atlantic

export DEBIAN=`/usr/bin/dpkg --search /usr/bin/dpkg >/dev/null 2>&1 && echo 1 || echo 0`

export KO_EXISTS=`cat /etc/modules 2>/dev/null | grep atlantic && echo 1 || echo 0`

ifeq "$(CC)" "gcc"
	ccflags-y := -Wall -DPCI_DEBUG
endif

ifeq "$(CC)" "clang-3.5"
	ccflags-y := -Wno-date-time -W --system-header-prefix=linux/ \
	-fsanitize=integer,address,undefined,alignment,bool,bounds,null,\
	enum,integer-divide-by-zero,shift,unreachable,unsigned-integer-overflow
endif

CFLAGS_aq_trace.o:=-I$(src)

ifneq ($(KERNELRELEASE),)
	$(TARGET)-objs:=aq_main.o aq_nic.o aq_pci_func.o aq_nic.o aq_vec.o aq_ring.o aq_ptp.o aq_filters.o \
	aq_hw_utils.o aq_ethtool.o aq_drvinfo.o hw_atl/hw_atl_a0.o hw_atl/hw_atl_b0.o hw_atl/hw_atl_utils.o\
	hw_atl/hw_atl_utils_fw2x.o aq_trace.o aq_phy.o\
	hw_atl/hw_atl_llh.o \
	hw_atl/hw_atl_fw_hostboot.o \
	hw_atl/hw_atl_fw_image.o \
	aq_compat.o \

	obj-m:=$(TARGET).o
else
	ifndef KDIR
		BUILD_DIR:=/lib/modules/$(shell uname -r)/build
	else
		BUILD_DIR:=$(KDIR)
	endif

	PWD:=$(shell pwd)

all:
	$(MAKE) -j4 -C $(BUILD_DIR) M=$(PWD) modules

dox:	.doxygen
	@doxygen $<

clean:
	$(MAKE) -j4 -C $(BUILD_DIR) M=$(PWD) clean
	@-rm -rdf doc/html 2 > /dev/null

load:
	modprobe ptp
	modprobe crc_itu_t
	insmod ./$(TARGET).ko

unload:
	rmmod ./$(TARGET).ko

install:
	@install -D -m 644 ${TARGET}.ko /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/aquantia/atlantic/${TARGET}.ko
	@depmod -a $(shell uname -r)
	@if [ "${DEBIAN}" = "1" ]; then \
		update-initramfs -u ; \
		if [ "${KO_EXISTS}" = "0" ]; then echo atlantic >> /etc/modules ; fi; \
	else \
		dracut --force ; \
	fi
	
uninstall:
	@if [ "${KO_EXISTS}" != "0" ]; then sed -in '/$TARGET/d' /etc/modules ; fi
	@rm -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/aquantia/atlantic/${TARGET}.ko
	@depmod -a $(shell uname -r)

endif


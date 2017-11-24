################################################################################
#
# aQuantia Ethernet Controller AQtion Linux Driver
# Copyright(c) 2014-2017 aQuantia Corporation.
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
# aQuantia Corporation, 105 E. Tasman Dr. San Jose, CA 95134, USA
#
################################################################################

#
# Makefile for the AQtion(tm) Ethernet driver
#


TARGET := atlantic

CC = gcc

ifeq "$(CC)" "gcc"
	ccflags-y := -Wall
endif

ifeq "$(CC)" "clang-3.5"
	ccflags-y := -Wno-date-time -W --system-header-prefix=linux/ \
	-fsanitize=integer,address,undefined,alignment,bool,bounds,null,\
	enum,integer-divide-by-zero,shift,unreachable,unsigned-integer-overflow
endif

ifneq ($(KERNELRELEASE),)
	$(TARGET)-objs:=aq_main.o aq_nic.o aq_pci_func.o aq_nic.o aq_vec.o aq_ring.o \
	aq_hw_utils.o aq_ethtool.o hw_atl/hw_atl_a0.o hw_atl/hw_atl_b0.o hw_atl/hw_atl_utils.o\
	hw_atl/hw_atl_llh.o

	obj-m:=$(TARGET).o
else
	ifndef KDIR
		BUILD_DIR:=/lib/modules/$(shell uname -r)/build
	else
		BUILD_DIR:=$(KDIR)
	endif

	PWD:=$(shell pwd)

all:
	$(MAKE) -j4 CC=$(CC) -C $(BUILD_DIR) M=$(PWD) modules

dox:	.doxygen
	@doxygen $<

clean:
	$(MAKE) -j4 -C $(BUILD_DIR) M=$(PWD) clean
	@-rm -rdf doc/html 2 > /dev/null

load:
	insmod ./$(TARGET).ko

unload:
	rmmod ./$(TARGET).ko

install:
	@install -D -m 644 ${TARGET}.ko /lib/modules/$(shell uname -r)/aquantia/${TARGET}.ko
	@depmod -a $(shell uname -r)

uninstall:
	@rm -f /lib/modules/$(shell uname -r)/aquantia/${TARGET}.ko
	@depmod -a $(shell uname -r)

endif


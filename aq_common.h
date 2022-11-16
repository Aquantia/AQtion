/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_common.h: Basic includes for all files in project. */

#ifndef AQ_COMMON_H
#define AQ_COMMON_H

#ifdef __KERNEL__
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/if_vlan.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include "ver.h"
#include "aq_cfg.h"
#include "aq_utils.h"
#include "aq_compat.h"
#endif

#define PCI_VENDOR_ID_AQUANTIA  0x1D6A

#define AQ_DEVICE_ID_0001	0x0001
#define AQ_DEVICE_ID_D100	0xD100
#define AQ_DEVICE_ID_D107	0xD107
#define AQ_DEVICE_ID_D108	0xD108
#define AQ_DEVICE_ID_D109	0xD109

#define AQ_DEVICE_ID_AQC100	0x00B1
#define AQ_DEVICE_ID_AQC107	0x07B1
#define AQ_DEVICE_ID_AQC108	0x08B1
#define AQ_DEVICE_ID_AQC109	0x09B1
#define AQ_DEVICE_ID_AQC111	0x11B1
#define AQ_DEVICE_ID_AQC112	0x12B1

#define AQ_DEVICE_ID_AQC100S	0x80B1
#define AQ_DEVICE_ID_AQC107S	0x87B1
#define AQ_DEVICE_ID_AQC108S	0x88B1
#define AQ_DEVICE_ID_AQC109S	0x89B1
#define AQ_DEVICE_ID_AQC111S	0x91B1
#define AQ_DEVICE_ID_AQC112S	0x92B1

#define AQ_DEVICE_ID_AQC113	0x04C0
#define AQ_DEVICE_ID_AQC113DEV	0x00C0
#define AQ_DEVICE_ID_AQC113C	0x14C0
#define AQ_DEVICE_ID_AQC113CA	0x34C0
#define AQ_DEVICE_ID_AQC115C	0x12C0
#define AQ_DEVICE_ID_AQC116C	0x11C0

#define AQ_DEVICE_ID_AQC113CS	0x94C0
#define AQ_DEVICE_ID_AQC114CS	0x93C0

#define AQ_CHIP_AQC100X		0xC100
#define AQ_CHIP_AQC107X		0xC107
#define AQ_CHIP_AQC108X		0xC108
#define AQ_CHIP_AQC109X		0xC109
#define AQ_CHIP_AQCC111X	0xC111
#define AQ_CHIP_AQCC112X	0xC112
#define AQ_CHIP_AQC111EX	0x111E
#define AQ_CHIP_AQC112EX	0x112E

#define AQ_FW_AQC100X		"mrvl/80B1.fw"
#define AQ_FW_AQC10XX		"mrvl/87B1.fw"
#define AQ_FW_AQC11XX		"mrvl/91B1.fw"
/* TODO: Same FW file name for all AQC113 devices. Need to revisit it. */
#define AQ_FW_AQC113X		"mrvl/04C0.clx"

#define HW_ATL_NIC_NAME "Marvell (aQuantia) AQtion 10Gbit Network Adapter"

#define AQ_HWREV_ANY	0
#define AQ_HWREV_1	1
#define AQ_HWREV_2	2
#define AQ_HWREV_3	3

#define AQ_NIC_RATE_10G		BIT(0)
#define AQ_NIC_RATE_5G		BIT(1)
#define AQ_NIC_RATE_2G5		BIT(2)
#define AQ_NIC_RATE_1G		BIT(3)
#define AQ_NIC_RATE_100M	BIT(4)
#define AQ_NIC_RATE_10M		BIT(5)
#define AQ_NIC_RATE_1G_HALF	BIT(6)
#define AQ_NIC_RATE_100M_HALF	BIT(7)
#define AQ_NIC_RATE_10M_HALF	BIT(8)

#define AQ_NIC_RATE_EEE_10G	BIT(9)
#define AQ_NIC_RATE_EEE_5G	BIT(10)
#define AQ_NIC_RATE_EEE_2G5	BIT(11)
#define AQ_NIC_RATE_EEE_1G	BIT(12)
#define AQ_NIC_RATE_EEE_100M	BIT(13)
#define AQ_NIC_RATE_EEE_MSK     (AQ_NIC_RATE_EEE_10G |\
				 AQ_NIC_RATE_EEE_5G |\
				 AQ_NIC_RATE_EEE_2G5 |\
				 AQ_NIC_RATE_EEE_1G |\
				 AQ_NIC_RATE_EEE_100M)

#define AQ_MIF_ID_ATL_A0 0x101U
#define AQ_MIF_ID_ATL_B0 0x102U
#define AQ_MIF_ID_ATL_B1 0x10AU
#define AQ_MIF_ID_ATL_BX 0x102U
#define AQ_MIF_ID_ATL_XX_MASK 0x307U
#define AQ_MIF_ID_ATL_FPGA_VAL 0x080U
#define AQ_MIF_ID_ATL_FPGA_MASK 0x0F0U
#define AQ_MIF_ID_FPGA_ATL2 0x103U
#define AQ_MIF_ID_ATL2B0 0x203U
#define AQ_MIF_ID_ANT_A0 0x200U
#define AQ_MIF_ID_ANT_XX_MASK 0x30FU

#endif /* AQ_COMMON_H */

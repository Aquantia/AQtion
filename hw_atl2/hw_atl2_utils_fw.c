// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 * Copyright (C) 2020 Marvell International Ltd.
 */

/* File hw_atl2_utils_fw2x.c: Definition of firmware 2.x functions for
 * Atlantic hardware abstraction layer.
 */

#include "aq_hw.h"
#include "aq_hw_utils.h"
#include "aq_nic.h"
#include "hw_atl/hw_atl_llh.h"
#include "hw_atl2_utils.h"
#include "hw_atl2_llh.h"
#include "hw_atl2_internal.h"

#define AQ_A2_FW_READ_TRY_MAX 1000

#define hw_atl2_shared_buffer_write(HW, ITEM, VARIABLE) \
{\
	BUILD_BUG_ON_MSG((offsetof(struct fw_interface_in, ITEM) % \
			 sizeof(u32)) != 0,\
			 "Unaligned write " # ITEM);\
	BUILD_BUG_ON_MSG((sizeof(VARIABLE) %  sizeof(u32)) != 0,\
			 "Unaligned write length " # ITEM);\
	hw_atl2_mif_shared_buf_write(HW,\
		(offsetof(struct fw_interface_in, ITEM) / sizeof(u32)),\
		(u32 *)&(VARIABLE), sizeof(VARIABLE) / sizeof(u32));\
}

#define hw_atl2_shared_buffer_get(HW, ITEM, VARIABLE) \
{\
	BUILD_BUG_ON_MSG((offsetof(struct fw_interface_in, ITEM) % \
			 sizeof(u32)) != 0,\
			 "Unaligned get " # ITEM);\
	BUILD_BUG_ON_MSG((sizeof(VARIABLE) %  sizeof(u32)) != 0,\
			 "Unaligned get length " # ITEM);\
	hw_atl2_mif_shared_buf_get(HW, \
		(offsetof(struct fw_interface_in, ITEM) / sizeof(u32)),\
		(u32 *)&(VARIABLE), \
		sizeof(VARIABLE) / sizeof(u32));\
}

/* This should never be used on non atomic fields,
 * treat any > u32 read as non atomic.
 */
#define hw_atl2_shared_buffer_read(HW, ITEM, VARIABLE) \
{\
	BUILD_BUG_ON_MSG((offsetof(struct fw_interface_out, ITEM) % \
			 sizeof(u32)) != 0,\
			 "Unaligned read " # ITEM);\
	BUILD_BUG_ON_MSG((sizeof(VARIABLE) %  sizeof(u32)) != 0,\
			 "Unaligned read length " # ITEM);\
	BUILD_BUG_ON_MSG(sizeof(VARIABLE) > sizeof(u32),\
			 "Non atomic read " # ITEM);\
	hw_atl2_mif_shared_buf_read(HW, \
		(offsetof(struct fw_interface_out, ITEM) / sizeof(u32)),\
		(u32 *)&(VARIABLE), sizeof(VARIABLE) / sizeof(u32));\
}

#define hw_atl2_shared_buffer_read_safe(HW, ITEM, DATA) \
({\
	BUILD_BUG_ON_MSG((offsetof(struct fw_interface_out, ITEM) % \
			 sizeof(u32)) != 0,\
			 "Unaligned read_safe " # ITEM);\
	BUILD_BUG_ON_MSG((sizeof(((struct fw_interface_out *)0)->ITEM) % \
			 sizeof(u32)) != 0,\
			 "Unaligned read_safe length " # ITEM);\
	hw_atl2_shared_buffer_read_block((HW), \
		(offsetof(struct fw_interface_out, ITEM) / sizeof(u32)),\
		sizeof(((struct fw_interface_out *)0)->ITEM) / sizeof(u32),\
		(DATA));\
})

static int hw_atl2_shared_buffer_read_block(struct aq_hw_s *self,
					    u32 offset, u32 dwords, void *data)
{
	struct transaction_counter_s tid1, tid2;
	int cnt = 0;

	do {
		do {
			hw_atl2_shared_buffer_read(self, transaction_id, tid1);
			cnt++;
			if (cnt > AQ_A2_FW_READ_TRY_MAX)
				return -ETIME;
			if (tid1.transaction_cnt_a != tid1.transaction_cnt_b)
				mdelay(1);
		} while (tid1.transaction_cnt_a != tid1.transaction_cnt_b);

		hw_atl2_mif_shared_buf_read(self, offset, (u32 *)data, dwords);

		hw_atl2_shared_buffer_read(self, transaction_id, tid2);

		cnt++;
		if (cnt > AQ_A2_FW_READ_TRY_MAX)
			return -ETIME;
	} while (tid2.transaction_cnt_a != tid2.transaction_cnt_b ||
		 tid1.transaction_cnt_a != tid2.transaction_cnt_a);

	return 0;
}

static inline int hw_atl2_shared_buffer_finish_ack(struct aq_hw_s *self)
{
	u32 val;
	int err;

	hw_atl2_mif_host_finished_write_set(self, 1U);
	err = readx_poll_timeout_atomic(hw_atl2_mif_mcp_finished_read_get,
					self, val, val == 0U,
					100, 100000U);
	WARN(err, "hw_atl2_shared_buffer_finish_ack");

	return err;
}

static inline void atl2_verify_sleep_proxy_s(void)
{
	const int base_offset = 0x12028;

	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_on_lan) != 0x12028 -
							       base_offset,
		"wake_on_lan invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[0]) !=
				0x12038 - base_offset,
			 "wakeUpPattern1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[1]) !=
				0x1204c - base_offset,
			 "wakeUpPattern2 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[2]) !=
				0x12060 - base_offset,
			 "wakeUpPattern3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[3]) !=
				0x12074 - base_offset,
			 "wakeUpPattern4 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[4]) !=
				0x12088 - base_offset,
			 "wakeUpPattern5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[5]) !=
				0x1209c - base_offset,
			 "wakeUpPattern6 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[6]) !=
				0x120b0 - base_offset,
			 "wakeUpPattern7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, wake_up_pattern[7]) !=
				0x120c4 - base_offset,
			 "wakeUpPattern8 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload) !=
				0x120d8 - base_offset,
			 "ipv4Offload invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[0]) !=
				0x120dc - base_offset,
			 "ipv4OffloadAddr1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[1]) !=
				0x120e0 - base_offset,
			 "ipv4OffloadAddr2 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[2]) !=
				0x120e4 - base_offset,
			 "ipv4OffloadAddr3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[3]) !=
				0x120e8 - base_offset,
			 "ipv4OffloadAddr4 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[4]) !=
				0x120ec - base_offset,
			 "ipv4OffloadAddr5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[5]) !=
				0x120f0 - base_offset,
			 "ipv4OffloadAddr6 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[6]) !=
				0x120f4 - base_offset,
			 "ipv4OffloadAddr7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv4_offload_addr[7]) !=
				0x120f8 - base_offset,
			 "ipv4OffloadAddr8 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload) !=
				0x1211c - base_offset,
			 "ipv6Offload invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[0]) !=
				0x12120 - base_offset,
			 "ipv6OffloadAddr1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[1]) !=
				0x12130 - base_offset,
			 "ipv6OffloadAddr2 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[2]) !=
				0x12140 - base_offset,
			 "ipv6OffloadAddr3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[3]) !=
				0x12150 - base_offset,
			 "ipv6OffloadAddr4 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[4]) !=
				0x12160 - base_offset,
			 "ipv6OffloadAddr5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[5]) !=
				0x12170 - base_offset,
			 "ipv6OffloadAddr6 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[6]) !=
				0x12180 - base_offset,
			 "ipv6OffloadAddr7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[7]) !=
				0x12190 - base_offset,
			 "ipv6OffloadAddr8 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[8]) !=
				0x121a0 - base_offset,
			 "ipv6OffloadAddr9 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[9]) !=
				0x121b0 - base_offset,
			 "ipv6OffloadAddr10 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[10]) !=
				0x121c0 - base_offset,
			 "ipv6OffloadAddr11 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[11]) !=
				0x121d0 - base_offset,
			 "ipv6OffloadAddr12 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[12]) !=
				0x121e0 - base_offset,
			 "ipv6OffloadAddr13 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[13]) !=
				0x121f0 - base_offset,
			 "ipv6OffloadAddr14 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[14]) !=
				0x12200 - base_offset,
			 "ipv6OffloadAddr15 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ipv6_offload_addr[15]) !=
				0x12210 - base_offset,
			 "ipv6OffloadAddr16 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[0]) !=
				0x12220 - base_offset,
			 "tcpPortOffload1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[2]) !=
				0x12224 - base_offset,
			 "tcpPortOffload3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[4]) !=
				0x12228 - base_offset,
			 "tcpPortOffload5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[6]) !=
				0x1222c - base_offset,
			 "tcpPortOffload7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[8]) !=
				0x12230 - base_offset,
			 "tcpPortOffload9 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[10]) !=
				0x12234 - base_offset,
			 "tcpPortOffload11 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[12]) !=
				0x12238 - base_offset,
			 "tcpPortOffload13 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, tcp_port_offload.port[14]) !=
				0x1223c - base_offset,
			 "tcpPortOffload15 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[0]) !=
				0x12240 - base_offset,
			 "udpPortOffload1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[2]) !=
				0x12244 - base_offset,
			 "udpPortOffload3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[4]) !=
				0x12248 - base_offset,
			 "udpPortOffload5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[6]) !=
				0x1224c - base_offset,
			 "udpPortOffload7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[8]) !=
				0x12250 - base_offset,
			 "udpPortOffload9 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[10]) !=
				0x12254 - base_offset,
			 "udpPortOffload11 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[12]) !=
				0x12258 - base_offset,
			 "udpPortOffload13 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, udp_port_offload.port[14]) !=
				0x1225c - base_offset,
			 "udpPortOffload15 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_offload) !=
				0x12260 - base_offset,
			 "ipv4KeepAliveOffload invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[0]) !=
				0x12268 - base_offset,
			 "ipv4KeepAliveConnection0 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[1]) !=
				0x12294 - base_offset,
			 "ipv4KeepAliveConnection1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[2]) !=
				0x122c0 - base_offset,
			 "ipv4KeepAliveConnection2 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[3]) !=
				0x122ec - base_offset,
			 "ipv4KeepAliveConnection3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[4]) !=
				0x12318 - base_offset,
			 "ipv4KeepAliveConnection4 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[5]) !=
				0x12344 - base_offset,
			 "ipv4KeepAliveConnection5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[6]) !=
				0x12370 - base_offset,
			 "ipv4KeepAliveConnection6 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[7]) !=
				0x1239c - base_offset,
			 "ipv4KeepAliveConnection7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[8]) != 0x123c8 -
								base_offset,
			 "ipv4KeepAliveConnection8 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[9]) != 0x123f4 -
								base_offset,
			 "ipv4KeepAliveConnection9 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[10]) != 0x12420 -
								base_offset,
			 "ipv4KeepAliveConnection10 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[11]) != 0x1244c -
								base_offset,
			 "ipv4KeepAliveConnection11 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[12]) != 0x12478 -
								base_offset,
			 "ipv4KeepAliveConnection12 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[13]) != 0x124a4 -
								base_offset,
			 "ipv4KeepAliveConnection13 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[14]) != 0x124d0 -
								base_offset,
			 "ipv4KeepAliveConnection14 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka4_connection[15]) != 0x124fc -
								base_offset,
			 "ipv4KeepAliveConnection15 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_offload) != 0x12528 -
								base_offset,
			 "ipv6KeepAliveOffload invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[0]) != 0x12530 -
								base_offset,
			 "ipv6KeepAliveConnection0 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[1]) != 0x12574 -
								base_offset,
			 "ipv6KeepAliveConnection1 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[2]) != 0x125b8 -
								base_offset,
			 "ipv6KeepAliveConnection2 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[3]) != 0x125fc -
								base_offset,
			 "ipv6KeepAliveConnection3 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[4]) != 0x12640 -
								base_offset,
			 "ipv6KeepAliveConnection4 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[5]) != 0x12684 -
								base_offset,
			 "ipv6KeepAliveConnection5 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[6]) != 0x126c8 -
								base_offset,
			 "ipv6KeepAliveConnection6 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[7]) != 0x1270c -
								base_offset,
			 "ipv6KeepAliveConnection7 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[8]) != 0x12750 -
								base_offset,
			 "ipv6KeepAliveConnection8 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[9]) != 0x12794 -
								base_offset,
			 "ipv6KeepAliveConnection9 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[10]) != 0x127d8 -
								base_offset,
			 "ipv6KeepAliveConnection10 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[11]) != 0x1281c -
								base_offset,
			 "ipv6KeepAliveConnection11 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[12]) != 0x12860 -
								base_offset,
			 "ipv6KeepAliveConnection12 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[13]) != 0x128a4 -
								base_offset,
			 "ipv6KeepAliveConnection13 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[14]) != 0x128e8 -
								base_offset,
			 "ipv6KeepAliveConnection14 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, ka6_connection[15]) != 0x1292c -
								base_offset,
			 "ipv6KeepAliveConnection15 invalid offset");
	BUILD_BUG_ON_MSG(
		offsetof(struct sleep_proxy_s, mdns_offload) != 0x12970 -
								base_offset,
			 "mdnsOffload invalid offset");
}

static int aq_a2_fw_init(struct aq_hw_s *self)
{
	struct request_policy_s request_policy;
	struct link_control_s link_control;
	u32 mtu;
	u32 val;
	int err;

	BUILD_BUG_ON_MSG(sizeof(struct link_options_s) != 0x4,
			 "linkOptions invalid size");
	BUILD_BUG_ON_MSG(sizeof(struct thermal_shutdown_s) != 0x4,
			 "thermalShutdown invalid size");
	BUILD_BUG_ON_MSG(sizeof(struct sleep_proxy_s) != 0x958,
			 "sleepProxy invalid size");
	BUILD_BUG_ON_MSG(sizeof(struct pause_quanta_s) != 0x18,
			 "pauseQuanta invalid size");
	BUILD_BUG_ON_MSG(sizeof(struct cable_diag_control_s) != 0x4,
			 "cableDiagControl invalid size");
 	BUILD_BUG_ON_MSG(sizeof(struct statistics_s) != 0x74,
			 "statistics_s invalid size");

	atl2_verify_sleep_proxy_s();

	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in, mtu) != 0,
			 "mtu invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in, mac_address) != 0x8,
			 "macAddress invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in,
				  link_control) != 0x10,
			 "linkControl invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in,
				  link_options) != 0x18,
			 "linkOptions invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in,
				  thermal_shutdown) != 0x20,
			 "thermalShutdown invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in, sleep_proxy) != 0x28,
			 "sleepProxy invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in,
				  pause_quanta) != 0x984,
			 "pauseQuanta invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_in,
				  cable_diag_control) != 0xA44,
			 "cableDiagControl invalid offset");

	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out, version) != 0x04,
			 "version invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out, link_status) != 0x14,
			 "linkStatus invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  wol_status) != 0x18,
			 "wolStatus invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  mac_health_monitor) != 0x610,
			 "macHealthMonitor invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  phy_health_monitor) != 0x620,
			 "phyHealthMonitor invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  cable_diag_status) != 0x630,
			 "cableDiagStatus invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  device_link_caps) != 0x648,
			 "deviceLinkCaps invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				 sleep_proxy_caps) != 0x650,
			 "sleepProxyCaps invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  lkp_link_caps) != 0x660,
			 "lkpLinkCaps invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out, core_dump) != 0x668,
			 "coreDump invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out, stats) != 0x700,
			 "stats invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  filter_caps) != 0x774,
			 "filter_caps invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out,
				  management_status) != 0x78c,
			 "management_status invalid offset");
	BUILD_BUG_ON_MSG(offsetof(struct fw_interface_out, trace) != 0x800,
			 "trace invalid offset");


	err = hw_atl2_utils_get_filter_caps(self);
	if (err)
		return err;

	hw_atl2_shared_buffer_get(self, link_control, link_control);
	link_control.mode = AQ_HOST_MODE_ACTIVE;
	hw_atl2_shared_buffer_write(self, link_control, link_control);

	hw_atl2_shared_buffer_get(self, mtu, mtu);
	mtu = HW_ATL2_MTU_JUMBO;
	hw_atl2_shared_buffer_write(self, mtu, mtu);

	hw_atl2_shared_buffer_get(self, request_policy, request_policy);
	request_policy.bcast.accept = 1;
	request_policy.bcast.queue_or_tc = 1;
	request_policy.bcast.rx_queue_tc_index = 0;
	request_policy.mcast.accept = 1;
	request_policy.mcast.queue_or_tc = 1;
	request_policy.mcast.rx_queue_tc_index = 0;
	request_policy.promisc.queue_or_tc = 1;
	request_policy.promisc.rx_queue_tc_index = 0;
	hw_atl2_shared_buffer_write(self, request_policy, request_policy);

	hw_atl2_mif_host_finished_write_set(self, 1U);
	err = readx_poll_timeout_atomic(hw_atl2_mif_mcp_finished_read_get,
					self, val, val == 0U,
					100, 5000000U);
	/* TODO: very long timeout (2s) temp fix
	 * for FW having long reaction for 0xe04
	 */
	WARN(err, "hw_atl2_shared_buffer_finish_ack");

	return err;
}

static int aq_a2_fw_deinit(struct aq_hw_s *self)
{
	struct link_control_s link_control;

	hw_atl2_shared_buffer_get(self, link_control, link_control);
	link_control.mode = AQ_HOST_MODE_SHUTDOWN;
	hw_atl2_shared_buffer_write(self, link_control, link_control);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static void a2_link_speed_mask2fw(u32 speed,
				  struct link_options_s *link_options)
{
	link_options->rate_10G = !!(speed & AQ_NIC_RATE_10G);
	link_options->rate_5G = !!(speed & AQ_NIC_RATE_5G);
	link_options->rate_N5G = link_options->rate_5G;
	link_options->rate_2P5G = !!(speed & AQ_NIC_RATE_2G5);
	link_options->rate_N2P5G = link_options->rate_2P5G;
	link_options->rate_1G = !!(speed & AQ_NIC_RATE_1G);
	link_options->rate_100M = !!(speed & AQ_NIC_RATE_100M);
	link_options->rate_10M = !!(speed & AQ_NIC_RATE_10M);

	link_options->rate_1G_hd = !!(speed & AQ_NIC_RATE_1G_HALF);
	link_options->rate_100M_hd = !!(speed & AQ_NIC_RATE_100M_HALF);
	link_options->rate_10M_hd = !!(speed & AQ_NIC_RATE_10M_HALF);
}

static u32 a2_fw_dev_to_eee_mask(struct device_link_caps_s *device_link_caps)
{
	u32 rate = 0;

	if (device_link_caps->eee_10G)
		rate |= AQ_NIC_RATE_EEE_10G;
	if (device_link_caps->eee_5G)
		rate |= AQ_NIC_RATE_EEE_5G;
	if (device_link_caps->eee_2P5G)
		rate |= AQ_NIC_RATE_EEE_2G5;
	if (device_link_caps->eee_1G)
		rate |= AQ_NIC_RATE_EEE_1G;
	if (device_link_caps->eee_100M)
		rate |= AQ_NIC_RATE_EEE_100M;

	return rate;
}

static u32 a2_fw_lkp_to_mask(struct lkp_link_caps_s *lkp_link_caps)
{
	u32 rate = 0;

	if (lkp_link_caps->rate_10G)
		rate |= AQ_NIC_RATE_10G;
	if (lkp_link_caps->rate_5G)
		rate |= AQ_NIC_RATE_5G;
	if (lkp_link_caps->rate_2P5G)
		rate |= AQ_NIC_RATE_2G5;
	if (lkp_link_caps->rate_1G)
		rate |= AQ_NIC_RATE_1G;
	if (lkp_link_caps->rate_1G_hd)
		rate |= AQ_NIC_RATE_1G_HALF;
	if (lkp_link_caps->rate_100M)
		rate |= AQ_NIC_RATE_100M;
	if (lkp_link_caps->rate_100M_hd)
		rate |= AQ_NIC_RATE_100M_HALF;
	if (lkp_link_caps->rate_10M)
		rate |= AQ_NIC_RATE_10M;
	if (lkp_link_caps->rate_10M_hd)
		rate |= AQ_NIC_RATE_10M_HALF;

	if (lkp_link_caps->eee_10G)
		rate |= AQ_NIC_RATE_EEE_10G;
	if (lkp_link_caps->eee_5G)
		rate |= AQ_NIC_RATE_EEE_5G;
	if (lkp_link_caps->eee_2P5G)
		rate |= AQ_NIC_RATE_EEE_2G5;
	if (lkp_link_caps->eee_1G)
		rate |= AQ_NIC_RATE_EEE_1G;
	if (lkp_link_caps->eee_100M)
		rate |= AQ_NIC_RATE_EEE_100M;

	return rate;
}

static int aq_a2_fw_set_link_speed(struct aq_hw_s *self, u32 speed)
{
	struct link_options_s link_options;

	hw_atl2_shared_buffer_get(self, link_options, link_options);
	link_options.link_up = 1U;
	a2_link_speed_mask2fw(speed, &link_options);
	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static void aq_a2_fw_set_mpi_flow_control(struct aq_hw_s *self,
					  struct link_options_s *link_options)
{
	u32 flow_control = self->aq_nic_cfg->fc.req;

	link_options->pause_rx = !!(flow_control & AQ_NIC_FC_RX);
	link_options->pause_tx = !!(flow_control & AQ_NIC_FC_TX);
}

static void aq_a2_fw_upd_eee_rate_bits(struct aq_hw_s *self,
				       struct link_options_s *link_options,
				       u32 eee_speeds)
{
	link_options->eee_10G =  !!(eee_speeds & AQ_NIC_RATE_EEE_10G);
	link_options->eee_5G = !!(eee_speeds & AQ_NIC_RATE_EEE_5G);
	link_options->eee_2P5G = !!(eee_speeds & AQ_NIC_RATE_EEE_2G5);
	link_options->eee_1G = !!(eee_speeds & AQ_NIC_RATE_EEE_1G);
	link_options->eee_100M = !!(eee_speeds & AQ_NIC_RATE_EEE_100M);
}

static int aq_a2_fw_set_state(struct aq_hw_s *self,
			      enum hal_atl_utils_fw_state_e state)
{
	struct link_options_s link_options;

	hw_atl2_shared_buffer_get(self, link_options, link_options);

	switch (state) {
	case MPI_INIT:
		link_options.link_up = 1U;
		aq_a2_fw_upd_eee_rate_bits(self, &link_options,
					   self->aq_nic_cfg->eee_speeds);
		aq_a2_fw_set_mpi_flow_control(self, &link_options);
		break;
	case MPI_DEINIT:
		link_options.link_up = 0U;
		break;
	case MPI_RESET:
	case MPI_POWER:
		/* No actions */
		break;
	}

	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static int aq_a2_fw_update_link_status(struct aq_hw_s *self)
{
	struct lkp_link_caps_s lkp_link_caps;
	struct link_status_s link_status;

	hw_atl2_shared_buffer_read(self, link_status, link_status);

	switch (link_status.link_rate) {
	case AQ_A2_FW_LINK_RATE_10G:
		self->aq_link_status.mbps = 10000;
		break;
	case AQ_A2_FW_LINK_RATE_5G:
		self->aq_link_status.mbps = 5000;
		break;
	case AQ_A2_FW_LINK_RATE_2G5:
		self->aq_link_status.mbps = 2500;
		break;
	case AQ_A2_FW_LINK_RATE_1G:
		self->aq_link_status.mbps = 1000;
		break;
	case AQ_A2_FW_LINK_RATE_100M:
		self->aq_link_status.mbps = 100;
		break;
	case AQ_A2_FW_LINK_RATE_10M:
		self->aq_link_status.mbps = 10;
		break;
	default:
		self->aq_link_status.mbps = 0;
	}
	self->aq_link_status.full_duplex = link_status.duplex;

	hw_atl2_shared_buffer_read(self, lkp_link_caps, lkp_link_caps);

	self->aq_link_status.lp_link_speed_msk =
				 a2_fw_lkp_to_mask(&lkp_link_caps);
	self->aq_link_status.lp_flow_control =
				((lkp_link_caps.pause_rx) ? AQ_NIC_FC_RX : 0) |
				((lkp_link_caps.pause_tx) ? AQ_NIC_FC_TX : 0);

	return 0;
}

static int aq_a2_fw_get_mac_permanent(struct aq_hw_s *self, u8 *mac)
{
	struct mac_address_aligned_s mac_address;

	hw_atl2_shared_buffer_get(self, mac_address, mac_address);
	ether_addr_copy(mac, (u8 *)mac_address.aligned.mac_address);

	return 0;
}

static void aq_a2_fill_a0_stats(struct aq_hw_s *self,
				struct statistics_s *stats)
{
	struct hw_atl2_priv *priv = (struct hw_atl2_priv *)self->priv;
	struct aq_stats_s *cs = &self->curr_stats;
	struct aq_stats_s curr_stats = *cs;
	bool corrupted_stats = false;

#define AQ_SDELTA(_N, _F)  \
do { \
	if (!corrupted_stats && \
	    ((s64)(stats->a0.msm._F - priv->last_stats.a0.msm._F)) >= 0) \
		curr_stats._N += stats->a0.msm._F - priv->last_stats.a0.msm._F;\
	else \
		corrupted_stats = true; \
} while (0)

	if (self->aq_link_status.mbps) {
		AQ_SDELTA(uprc, rx_unicast_frames);
		AQ_SDELTA(mprc, rx_multicast_frames);
		AQ_SDELTA(bprc, rx_broadcast_frames);
		AQ_SDELTA(erpr, rx_error_frames);

		AQ_SDELTA(uptc, tx_unicast_frames);
		AQ_SDELTA(mptc, tx_multicast_frames);
		AQ_SDELTA(bptc, tx_broadcast_frames);
		AQ_SDELTA(erpt, tx_errors);

		AQ_SDELTA(ubrc, rx_unicast_octets);
		AQ_SDELTA(ubtc, tx_unicast_octets);
		AQ_SDELTA(mbrc, rx_multicast_octets);
		AQ_SDELTA(mbtc, tx_multicast_octets);
		AQ_SDELTA(bbrc, rx_broadcast_octets);
		AQ_SDELTA(bbtc, tx_broadcast_octets);

		if (!corrupted_stats)
			*cs = curr_stats;
	}
#undef AQ_SDELTA

}

static void aq_a2_fill_b0_stats(struct aq_hw_s *self,
				struct statistics_s *stats)
{
	struct hw_atl2_priv *priv = (struct hw_atl2_priv *)self->priv;
	struct aq_stats_s *cs = &self->curr_stats;
	struct aq_stats_s curr_stats = *cs;
	bool corrupted_stats = false;

#define AQ_SDELTA(_N, _F)  \
do { \
	if (!corrupted_stats && \
	    ((s64)(stats->b0._F - priv->last_stats.b0._F)) >= 0) \
		curr_stats._N += stats->b0._F - priv->last_stats.b0._F; \
	else \
		corrupted_stats = true; \
} while (0)

	if (self->aq_link_status.mbps) {
		AQ_SDELTA(uprc, rx_unicast_frames);
		AQ_SDELTA(mprc, rx_multicast_frames);
		AQ_SDELTA(bprc, rx_broadcast_frames);
		AQ_SDELTA(erpr, rx_errors);
		AQ_SDELTA(brc, rx_good_octets);

		AQ_SDELTA(uptc, tx_unicast_frames);
		AQ_SDELTA(mptc, tx_multicast_frames);
		AQ_SDELTA(bptc, tx_broadcast_frames);
		AQ_SDELTA(erpt, tx_errors);
		AQ_SDELTA(btc, tx_good_octets);

		if (!corrupted_stats)
			*cs = curr_stats;
	}
#undef AQ_SDELTA

}

static int aq_a2_fw_update_stats(struct aq_hw_s *self)
{
	struct hw_atl2_priv *priv = (struct hw_atl2_priv *)self->priv;
	struct aq_stats_s *cs = &self->curr_stats;
	struct statistics_s stats;
	struct version_s version;
	int err;

	err = hw_atl2_shared_buffer_read_safe(self, version, &version);
	if (err)
		return err;

	err = hw_atl2_shared_buffer_read_safe(self, stats, &stats);
	if (err)
		return err;

	if (version.drv_iface_ver == AQ_A2_FW_INTERFACE_A0)
		aq_a2_fill_a0_stats(self, &stats);
	else
		aq_a2_fill_b0_stats(self, &stats);

	cs->dma_pkt_rc = hw_atl_stats_rx_dma_good_pkt_counter_get(self);
	cs->dma_pkt_tc = hw_atl_stats_tx_dma_good_pkt_counter_get(self);
	cs->dma_oct_rc = hw_atl_stats_rx_dma_good_octet_counter_get(self);
	cs->dma_oct_tc = hw_atl_stats_tx_dma_good_octet_counter_get(self);
	cs->dpc = hw_atl_rpb_rx_dma_drop_pkt_cnt_get(self);

	memcpy(&priv->last_stats, &stats, sizeof(stats));

	return 0;
}

static int aq_a2_fw_get_phy_temp(struct aq_hw_s *self, int *temp)
{
	struct phy_health_monitor_s phy_health_monitor;

	hw_atl2_shared_buffer_read_safe(self, phy_health_monitor,
					&phy_health_monitor);

	*temp = (int8_t)phy_health_monitor.phy_temperature * 1000;
	return 0;
}

static int aq_a2_fw_get_mac_temp(struct aq_hw_s *self, int *temp)
{
	/* There's only one temperature sensor on A2, use it for
	 * both MAC and PHY.
	 */
	return aq_a2_fw_get_phy_temp(self, temp);
}

static int aq_a2_fw_get_cable_diag_capable(struct aq_hw_s *self, bool *capable)
{
	struct device_caps_s device_caps;
	int err;

	err = hw_atl2_shared_buffer_read_safe(self, device_caps, &device_caps);
	if (err)
		return err;

	*capable = !!(device_caps.cable_diag);
	return 0;
}

static int aq_a2_fw_run_tdr_diag(struct aq_hw_s *self)
{
	struct hw_atl2_priv *priv = (struct hw_atl2_priv *)self->priv;
	struct cable_diag_control_s cable_diag_control;
	struct cable_diag_status_s cable_diag_status;
	bool diag_capable;
	int err = 0;

	/* Check if capability is available */
	err = aq_a2_fw_get_cable_diag_capable(self, &diag_capable);
	if (err)
		return err;
	if (!diag_capable)
		return -EOPNOTSUPP;

	hw_atl2_shared_buffer_get(self, cable_diag_control, cable_diag_control);
	cable_diag_control.toggle ^= 1U;

	hw_atl2_shared_buffer_write(self, cable_diag_control,
				    cable_diag_control);

	err = hw_atl2_shared_buffer_finish_ack(self);
	if (err)
		return err;

	err = hw_atl2_shared_buffer_read_safe(self,
					      cable_diag_status,
					      &cable_diag_status);
	if (err)
		return err;

	priv->cable_diag_tid1 = cable_diag_status.transact_id;
	return err;
}

static int aq_a2_fw_get_diag_data(struct aq_hw_s *self, struct aq_diag_s *diag)
{
	struct hw_atl2_priv *priv = (struct hw_atl2_priv *)self->priv;
	struct cable_diag_status_s cable_diag_status;
	int i = 0;
	int err;

	err = hw_atl2_shared_buffer_read_safe(self,
					      cable_diag_status,
					      &cable_diag_status);
	if (err)
		return -EBUSY;

	/* Driver should monitor the transaction ID -
	 * incrementing means that cable diagnostics is completed.
	 */
	if (cable_diag_status.transact_id == priv->cable_diag_tid1)
		return -EBUSY;

	/* Completion code: 0 means OK */
	if (cable_diag_status.status != 0)
		return -ETIME;

	for (i = 0; i < 4; i++) {
		diag->cable_diag[i].fault =
			cable_diag_status.lane_data[i].result_code;
		diag->cable_diag[i].distance =
			cable_diag_status.lane_data[i].dist;
		diag->cable_diag[i].far_distance =
			cable_diag_status.lane_data[i].far_dist;
	}

	return err;
}

static int aq_a2_fw_set_wol_params(struct aq_hw_s *self, const u8 *mac, u32 wol)
{
	struct link_control_s link_control;
	struct mac_address_aligned_s mac_address;
	struct wake_on_lan_s wake_on_lan;

	memcpy(mac_address.aligned.mac_address, mac, ETH_ALEN);
	hw_atl2_shared_buffer_write(self, mac_address, mac_address);

	memset(&wake_on_lan, 0, sizeof(wake_on_lan));

	if (wol & WAKE_MAGIC)
		wake_on_lan.wake_on_magic_packet = 1U;

	if (wol & (WAKE_PHY | AQ_FW_WAKE_ON_LINK_RTPM))
		wake_on_lan.wake_on_link_up = 1U;

	hw_atl2_shared_buffer_write(self, sleep_proxy, wake_on_lan);

	hw_atl2_shared_buffer_get(self, link_control, link_control);
	link_control.mode = AQ_HOST_MODE_SLEEP_PROXY;
	hw_atl2_shared_buffer_write(self, link_control, link_control);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static int aq_a2_fw_set_power(struct aq_hw_s *self, unsigned int power_state,
			      const u8 *mac, u32 wol)
{
	int err = 0;

	if (wol)
		err = aq_a2_fw_set_wol_params(self, mac, wol);

	return err;
}

static int aq_a2_fw_set_eee_rate(struct aq_hw_s *self, u32 speed)
{
	struct link_options_s link_options;

	hw_atl2_shared_buffer_get(self, link_options, link_options);

	aq_a2_fw_upd_eee_rate_bits(self, &link_options, speed);

	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static int aq_a2_fw_get_eee_rate(struct aq_hw_s *self, u32 *rate,
				 u32 *supported_rates)
{
	struct device_link_caps_s device_link_caps;
	struct lkp_link_caps_s lkp_link_caps;

	hw_atl2_shared_buffer_read(self, device_link_caps, device_link_caps);
	hw_atl2_shared_buffer_read(self, lkp_link_caps, lkp_link_caps);

	*supported_rates = a2_fw_dev_to_eee_mask(&device_link_caps);
	*rate = a2_fw_lkp_to_mask(&lkp_link_caps);

	return 0;
}

static int aq_a2_fw_renegotiate(struct aq_hw_s *self)
{
	struct link_options_s link_options;
	int err;

	hw_atl2_shared_buffer_get(self, link_options, link_options);
	link_options.link_renegotiate = 1U;
	hw_atl2_shared_buffer_write(self, link_options, link_options);

	err = hw_atl2_shared_buffer_finish_ack(self);

	/* We should put renegotiate status back to zero
	 * after command completes
	 */
	link_options.link_renegotiate = 0U;
	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return err;
}

static int aq_a2_fw_set_flow_control(struct aq_hw_s *self)
{
	struct link_options_s link_options;

	hw_atl2_shared_buffer_get(self, link_options, link_options);

	aq_a2_fw_set_mpi_flow_control(self, &link_options);

	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static u32 aq_a2_fw_get_flow_control(struct aq_hw_s *self, u32 *fcmode)
{
	struct link_status_s link_status;

	hw_atl2_shared_buffer_read(self, link_status, link_status);

	*fcmode = ((link_status.pause_rx) ? AQ_NIC_FC_RX : 0) |
		  ((link_status.pause_tx) ? AQ_NIC_FC_TX : 0);
	return 0;
}

static int aq_a2_fw_set_phyloopback(struct aq_hw_s *self, u32 mode, bool enable)
{
	struct link_options_s link_options;

	hw_atl2_shared_buffer_get(self, link_options, link_options);

	switch (mode) {
	case AQ_HW_LOOPBACK_PHYINT_SYS:
		link_options.internal_loopback = enable;
		break;
	case AQ_HW_LOOPBACK_PHYEXT_SYS:
		link_options.external_loopback = enable;
		break;
	default:
		return -EINVAL;
	}

	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return hw_atl2_shared_buffer_finish_ack(self);
}

static u32 aq_a2_fw_get_link_capabilities(struct aq_hw_s *self)
{
	u32 val;

	val =  BIT(CAPS_LO_WAKE_ON_LINK_FORCED);

	return val;
}

u32 hw_atl2_utils_get_fw_version(struct aq_hw_s *self)
{
	struct version_s version;

	hw_atl2_shared_buffer_read_safe(self, version, &version);

	/* A2 FW version is stored in reverse order */
	return version.bundle.major << 24 |
	       version.bundle.minor << 16 |
	       version.bundle.build;
}

int hw_atl2_utils_get_version(struct aq_hw_s *self, struct version_s *v)
{
	hw_atl2_shared_buffer_read_safe(self, version, v);

	return 0;
}

int hw_atl2_utils_get_filter_caps(struct aq_hw_s *self)
{
	struct hw_atl2_priv *priv = (struct hw_atl2_priv *)self->priv;
	struct filter_caps_s filter_caps;
	u32 tag_top;
	int err;

	err = hw_atl2_shared_buffer_read_safe(self, filter_caps, &filter_caps);
	if (err)
		return err;

	priv->art_base_index = filter_caps.rslv_tbl_base_index * 8;
	priv->art_count = filter_caps.rslv_tbl_count * 8;
	if (priv->art_count == 0)
		priv->art_count = 128;
	priv->l2_filters_base_index = filter_caps.l2_filters_base_index;
	priv->l2_filter_count = filter_caps.l2_filter_count;
	priv->etype_filter_base_index = filter_caps.ethertype_filter_base_index;
	priv->etype_filter_count = filter_caps.ethertype_filter_count;
	priv->etype_filter_tag_top =
		(priv->etype_filter_count >= HW_ATL2_RPF_ETYPE_TAGS) ?
		 (HW_ATL2_RPF_ETYPE_TAGS) : (HW_ATL2_RPF_ETYPE_TAGS >> 1);
	priv->vlan_filter_base_index = filter_caps.vlan_filter_base_index;
	/* 0 - no tag, 1 - reserved for vlan-filter-offload filters */
	tag_top =
		  (filter_caps.vlan_filter_count == HW_ATL2_RPF_VLAN_FILTERS) ?
		  (HW_ATL2_RPF_VLAN_FILTERS - 2) :
		  (HW_ATL2_RPF_VLAN_FILTERS / 2 - 2);
	priv->vlan_filter_count = min_t(u32, filter_caps.vlan_filter_count - 2,
					tag_top);
	priv->l3_v4_filter_base_index = filter_caps.l3_ip4_filter_base_index;
	priv->l3_v4_filter_count = min_t(u32, filter_caps.l3_ip4_filter_count,
					  HW_ATL2_RPF_L3V4_FILTERS - 1);
	priv->l3_v6_filter_base_index = filter_caps.l3_ip6_filter_base_index;
	priv->l3_v6_filter_count = filter_caps.l3_ip6_filter_count;
	priv->l4_filter_base_index = filter_caps.l4_filter_base_index;
	priv->l4_filter_count = min_t(u32, filter_caps.l4_filter_count,
				      HW_ATL2_RPF_L4_FILTERS - 1);

	return 0;
}

int hw_atl2_utils_set_filter_policy(struct aq_hw_s *self, bool promisc,
				    bool allmulti)
{
	struct request_policy_s request_policy;

	hw_atl2_shared_buffer_get(self, request_policy, request_policy);

	request_policy.promisc.all = promisc;
	request_policy.promisc.mcast = allmulti;

	hw_atl2_shared_buffer_write(self, request_policy, request_policy);
	return hw_atl2_shared_buffer_finish_ack(self);
}

static int aq_a2_fw_set_downshift(struct aq_hw_s *self, u32 counter)
{
	struct link_options_s link_options;

	hw_atl2_shared_buffer_get(self, link_options, link_options);
	link_options.downshift = !!counter;
	link_options.downshift_retry = counter;
	hw_atl2_shared_buffer_write(self, link_options, link_options);

	return hw_atl2_shared_buffer_finish_ack(self);
}

/* The API is designed for hostboot implementation - doesn't wait for FW ACK */
int hw_atl2_utils_set_db_status(struct aq_hw_s *self, u32 offset, u32 length)
{
	struct data_buffer_status_s data_buffer_status;

	data_buffer_status.data_offset = offset;
	data_buffer_status.data_length = length;
	hw_atl2_shared_buffer_write(self, data_buffer_status, data_buffer_status);

	return 0;
}

const struct aq_fw_ops aq_a2_fw_ops = {
	.init               = aq_a2_fw_init,
	.deinit             = aq_a2_fw_deinit,
	.reset              = NULL,
	.renegotiate        = aq_a2_fw_renegotiate,
	.get_mac_permanent  = aq_a2_fw_get_mac_permanent,
	.set_link_speed     = aq_a2_fw_set_link_speed,
	.set_state          = aq_a2_fw_set_state,
	.update_link_status = aq_a2_fw_update_link_status,
	.update_stats       = aq_a2_fw_update_stats,
	.set_power          = aq_a2_fw_set_power,
	.get_mac_temp       = aq_a2_fw_get_mac_temp,
	.get_phy_temp       = aq_a2_fw_get_phy_temp,
	.get_cable_len      = NULL,
	.get_cable_diag_capable = aq_a2_fw_get_cable_diag_capable,
	.run_tdr_diag       = aq_a2_fw_run_tdr_diag,
	.get_diag_data      = aq_a2_fw_get_diag_data,
	.get_snr_margins    = NULL,
	.set_eee_rate       = aq_a2_fw_set_eee_rate,
	.get_eee_rate       = aq_a2_fw_get_eee_rate,
	.set_flow_control   = aq_a2_fw_set_flow_control,
	.get_flow_control   = aq_a2_fw_get_flow_control,
	.send_fw_request    = NULL,
	.enable_ptp         = NULL,
	.led_control        = NULL,
	.set_phyloopback    = aq_a2_fw_set_phyloopback,
	.get_link_capabilities = aq_a2_fw_get_link_capabilities,
	.set_downshift      = aq_a2_fw_set_downshift,
};

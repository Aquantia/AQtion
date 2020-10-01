/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_cfg.h: Definition of configuration parameters and constants. */

#ifndef AQ_CFG_H
#define AQ_CFG_H

#define AQ_CFG_VECS_DEF   8U
#define AQ_CFG_TCS_DEF    1U

#define AQ_CFG_TXDS_DEF    4096U
#define AQ_CFG_RXDS_DEF    2048U

#define AQ_CFG_IS_POLLING_DEF 0U

#define AQ_CFG_FORCE_LEGACY_INT 0U

#define AQ_CFG_INTERRUPT_MODERATION_OFF		0
#define AQ_CFG_INTERRUPT_MODERATION_ON		1
#define AQ_CFG_INTERRUPT_MODERATION_AUTO	0xFFFFU

#define AQ_CFG_INTERRUPT_MODERATION_USEC_MAX (0x1FF * 2)

#define AQ_CFG_IRQ_MASK                      0x7FFU

#define AQ_CFG_VECS_MAX   8U
#define AQ_CFG_TCS_MAX    8U

#define AQ_CFG_TX_FRAME_MAX  (16U * 1024U)
#define AQ_CFG_RX_FRAME_MAX  (2U * 1024U)

#define AQ_CFG_TX_CLEAN_BUDGET 256U

#define AQ_CFG_RX_HDR_SIZE 256U

/* LRO */
#define AQ_CFG_IS_LRO_DEF           1U

/* PTP */
#define AQ_CFG_PTP_DEF              1U

/* RSS */
#define AQ_CFG_RSS_INDIRECTION_TABLE_MAX  64U
#define AQ_CFG_RSS_HASHKEY_SIZE           40U

#define AQ_CFG_IS_RSS_DEF           1U
#define AQ_CFG_NUM_RSS_QUEUES_DEF   AQ_CFG_VECS_DEF
#define AQ_CFG_RSS_BASE_CPU_NUM_DEF 0U

#define AQ_CFG_PCI_FUNC_MSIX_IRQS   11U
#define AQ_CFG_PCI_FUNC_PORTS       2U

#define AQ_CFG_SERVICE_TIMER_INTERVAL    (1 * HZ)
#define AQ_CFG_POLLING_TIMER_INTERVAL   ((unsigned int)(2 * HZ))

#define AQ_CFG_SKB_FRAGS_MAX   32U

/* Number of descriptors available in one ring to resume this ring queue
 */
#define AQ_CFG_RESTART_DESC_THRES   (AQ_CFG_SKB_FRAGS_MAX * 2)

#define AQ_CFG_NAPI_WEIGHT     64U

/*#define AQ_CFG_MAC_ADDR_PERMANENT {0x30, 0x0E, 0xE3, 0x12, 0x34, 0x56}*/

#define AQ_CFG_FC_MODE AQ_NIC_FC_FULL

/* Default WOL modes used on initialization */
#define AQ_CFG_WOL_MODES WAKE_MAGIC

#define AQ_CFG_SPEED_MSK  0xFFFFU	/* 0xFFFFU==auto_neg */

#define AQ_CFG_IS_AUTONEG_DEF       1U
#define AQ_CFG_MTU_DEF              1514U

/* When defined, driver ensures fastest link up time
 * on start and on ifup. Full hardware reset sequence
 * is skipped in that case, we rely on existing FW state.
 * 
 * #define AQ_CFG_FAST_START
 */

/* HW bug workaround:
 * Disable RSS for UDP using rx flow filter 0.
 */
#define AQ_CFG_UDP_RSS_DISABLE	0

/* Reset datapath only instead of full global reset
 */
#ifndef AQ_CFG_NO_MCP_RESET
#define AQ_CFG_NO_MCP_RESET 0
#endif

#define AQ_CFG_LOCK_TRYS   100U

#define AQ_CFG_DRV_AUTHOR      "Marvell"
#define AQ_CFG_DRV_DESC        "Marvell (Aquantia) Corporation(R) Network Driver"
#define AQ_CFG_DRV_NAME        "atlantic"
#define AQ_CFG_DRV_VERSION	__stringify(NIC_MAJOR_DRIVER_VERSION)"."\
				__stringify(NIC_MINOR_DRIVER_VERSION)"."\
				__stringify(NIC_BUILD_DRIVER_VERSION)"."\
				__stringify(NIC_REVISION_DRIVER_VERSION) \
				AQ_CFG_DRV_VERSION_SUFFIX

#endif /* AQ_CFG_H */

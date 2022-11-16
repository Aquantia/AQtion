#ifndef AQ_DASH_INTERNAL_H
#define AQ_DASH_INTERNAL_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/timer.h>

#include "aq_dash.h"
#include "aq_nic.h"
#include "aq_hw.h"

/* family name */
#define AQ_DASH_GENL_NAME "aq-dash"

/* interval in milisecond */
#define AQ_DASH_NOTIFICATION_INTERVAL 200

static struct genl_family aq_dash_nl_family;
struct timer_list timer;
const char atl_driver_name[] = "atlantic";

static const struct nla_policy aq_dash_nl_policy[AQ_DASH_ATTR_MAX + 1] = {
	[AQ_DASH_ATTR_CMD_ID]		= {.type = NLA_S32},
	[AQ_DASH_ATTR_MSG_DATA_LEN]	= {.type = NLA_S32},
	[AQ_DASH_ATTR_IFNAME]		= {.type = NLA_NUL_STRING},
	[AQ_DASH_ATTR_MSG_DATA]		= {.type = NLA_NUL_STRING},
};

struct __packed aq_dash_rpc_hdr {
	enum aq_dash_msg_id id;
	uint32_t size;
};

/* Shared structure between user/driver */
struct __packed aq_dash_params{
	u32 method_id;
	u32 in_data_size;
	u32 out_data_size;
	u32 status;
	u8  message[1514 + 4];
};

/* RPC messages id */
enum aq_dash_rpc_msg_id {
	AQ_DASH_SET_CONFIG = 0x30, /* Static DASH configuration */
	AQ_DASH_READ_REQUEST = 0x31, /* Pending request from Firmware */
	AQ_DASH_POWER_OP_ACK = 0x35, /* Graceful power operation confirmation */
};

/* RPC dash event response buffer */
struct __packed aq_dash_event {
	u32 size;
	u8 data[508];
};

/* RPC dash event request buffer */
struct aq_dash_request {
	u32 msg_id;
	u32 size;
	u16 power_state;
	u16 : 16;
};

struct __packed aq_dash_event_buffer {
	u32 msg_id;
	u32 size;
	u16 data[500];
};

static const struct genl_multicast_group aq_dash_groups[] = {
	[AQ_DASH_EVENT_GROUP] = {.name = "aq_dash_event",},
};

#endif

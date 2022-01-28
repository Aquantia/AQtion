#ifndef AQ_DASH_H
#define AQ_DASH_H

/* attributes */
enum aq_dash_msg_attrs {
	AQ_DASH_ATTR_UNSPEC,
	AQ_DASH_ATTR_IFNAME,
	AQ_DASH_ATTR_CMD_ID,
	AQ_DASH_ATTR_MSG_DATA,
	AQ_DASH_ATTR_MSG_DATA_LEN,
	AQ_DASH_ATTR_EVENT,
	AQ_DASH_ATTR_MAX,
};

/* commands */
enum aq_dash_nl_command {
	AQ_DASH_CMD_UNSPEC,
	/* Set/Get DASH config command
	 * Manadatory attributes:
		AQ_DASH_ATTR_IFNAME,
		AQ_DASH_ATTR_CMD_ID,
		AQ_DASH_ATTR_MSG_DATA and
		AQ_DASH_ATTR_MSG_DATA_LEN */
	AQ_DASH_CMD_FWREQ,

	/* FW upgrade/Power management event */
	AQ_DASH_EVENT,

	AQ_DASH_CMD_MAX,
};

/* dash message ids */
enum aq_dash_msg_id {
	AQ_DASH_SEND_DATA, /* Sends DATA to FW */
	AQ_DASH_GET_DATA, /* Gets DATA from FW */
};

/* multicast group */
enum genl_test_multicast_groups {
	AQ_DASH_EVENT_GROUP,
};

#endif

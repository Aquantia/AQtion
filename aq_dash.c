/*
 * File aq_dash.c : Generic Netlink related APIs
 */

#include "aq_dash_internal.h"

static struct sk_buff *aq_dash_reply_create(void)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
}

static void *aq_dash_reply_init(struct sk_buff *skb, struct genl_info *info)
{
	void *hdr = NULL;

	hdr = genlmsg_put(skb, info->snd_portid, info->snd_seq,
			&aq_dash_nl_family, NLMSG_DONE, info->genlhdr->cmd);

	if (hdr == NULL) {
		printk(KERN_ERR "Error: Reply message creation failed\n");
		nlmsg_free(skb);
	}

	return hdr;
}

static int aq_dash_reply_add_attr(struct sk_buff *skb,
				  const enum aq_dash_msg_attrs attr,
				  const u16 size,
				  const u8 *data)
{
	if (unlikely(skb == NULL))
		return false;

	if (nla_put(skb, attr, size, data) != 0) {
		printk(KERN_ERR "Error: failed to put reply attribute\n");
		return false;
	}

	return true;
}

static int aq_dash_reply_send(struct sk_buff *msg,
			 void *hdr,
			 struct genl_info *info)
{
	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

int aq_dash_send_to_user(struct genl_info *info, u8 *requested_data, u16 rpc_size)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;

	msg = aq_dash_reply_create();
	if (unlikely(msg == NULL))
		return -ENOBUFS;

	hdr = aq_dash_reply_init(msg, info);
	if (unlikely(hdr == NULL))
		return -EMSGSIZE;

	if (aq_dash_reply_add_attr(msg, AQ_DASH_ATTR_MSG_DATA,
				   rpc_size, requested_data) == false) {
		printk(KERN_ERR "Failed to add ATTR_MSG_DATA attribute\n");
		genlmsg_cancel(msg, hdr);
		return -EMSGSIZE;
	}

	if (aq_dash_reply_send(msg, hdr, info) != 0)
		printk(KERN_ERR "Error: nl_reply_send failed\n");

	return 0;
}

/* Returns true, if the given net_device was allocated by atlantic driver.
 */
bool is_atl_device(const struct net_device *dev)
{
	static size_t atl_len;

	if (unlikely(atl_len == 0))
		atl_len = strlen(atl_driver_name);

	if (likely(dev && dev->dev.parent)) {
		const char *driver_name = dev_driver_string(dev->dev.parent);
		const size_t len = min_t(size_t, atl_len, strlen(driver_name));

		return (len == atl_len) &&
		       !strncmp(driver_name, atl_driver_name, len);
	}

	return false;
}

/* Get net_device by ifname
 * Returns NULL on error, net_device pointer otherwise.
 */
static struct net_device *aq_dash_get_dev_by_name(const char *dev_name,
						struct genl_info *info)
{
        struct net_device *netdev = NULL;

        if (dev_name == NULL)
                return NULL;

        netdev = dev_get_by_name(genl_info_net(info), dev_name);
        if (unlikely(netdev == NULL)) {
                printk(KERN_ERR "No matching device found\n");
                return NULL;
        }

        if (unlikely(!is_atl_device(netdev))) {
                printk(KERN_ERR
                        "Device(%s) is not an ATL device or a wrong driver is used\n", dev_name);
                goto err_devput;
        }
        return netdev;

err_devput:
        dev_put(netdev);
        return NULL;
}

static struct net_device * aq_dash_get_ndev_or_null(struct genl_info *info,
					 const enum aq_dash_msg_attrs attr)
{
	const char *ifname;

	if (likely(!info->attrs[attr]))
		return NULL;

	ifname = (char *)nla_data(info->attrs[attr]);

	return aq_dash_get_dev_by_name(ifname, info);
}

static int aq_dash_get_data(struct aq_hw_s *self,
			    u8 *dash_cfg,
			    u16 *size,
			    u8 **resp_ptr)
{
	struct hw_atl_utils_fw_rpc *prpc = NULL;
	struct aq_dash_rpc_hdr *hdr = NULL;
	u32 word_count = 0;
	u32 *u32ptr = NULL;
	int ret = 0;

	if (!dash_cfg) {
		ret = -EINVAL;
		goto error_exit;
	}

	ret = hw_atl_utils_fw_rpc_wait(self, &prpc);
	if (ret < 0)
		goto error_exit;

	memcpy(&self->rpc, dash_cfg, *size);
	ret = hw_atl_utils_fw_rpc_call(self, *size);
	if (ret < 0)
		goto error_exit;

	ret = hw_atl_utils_fw_rpc_wait(self, &prpc);
	if (ret < 0)
		goto error_exit;

	hdr = (struct aq_dash_rpc_hdr *) kmalloc(sizeof(*hdr), GFP_KERNEL);
	if (hdr == NULL) {
		ret =  -ENOMEM;
		goto error_exit;
	}

	/* read FW response header */
	ret = hw_atl_utils_fw_downld_dwords(self,
					    self->rpc_addr,
					    (u32 *)(void *)hdr,
					    (sizeof(hdr) + sizeof(u32) -
					     sizeof(u8))/ sizeof(u32));
	if (ret < 0)
		goto error_exit;

	*size = hdr->size;
	word_count = (*size + 3) / sizeof(u32);

	u32ptr = (u32 *) kmalloc((word_count * sizeof(u32)), GFP_KERNEL);
	if (u32ptr == NULL) {
		ret = -ENOMEM;
		goto error_exit;
	}

	/* read FW response data */
	memset(u32ptr, 0, (word_count * sizeof(u32)));
	ret = hw_atl_utils_fw_downld_dwords(self,
					    self->rpc_addr,
					    u32ptr,
					    word_count);
	if (!ret)
		*resp_ptr = (u8 *)u32ptr;

error_exit:
	return ret;
}

static int  aq_dash_send_data(struct aq_hw_s *self,
			      u8 *dash_cfg,
			      u16 rpc_size)
{
	struct hw_atl_utils_fw_rpc *prpc = NULL;
	int ret = 0;

	if (!dash_cfg) {
		ret = -EINVAL;
		goto err_exit;
	}

	ret = hw_atl_utils_fw_rpc_wait(self, &prpc);
	if (ret < 0)
		goto err_exit;

	memcpy(&self->rpc, dash_cfg, rpc_size);
	ret = hw_atl_utils_fw_rpc_call(self, rpc_size);

err_exit:
	return ret;
}

/* Sends multicast message to userspace */
static int aq_dash_indicate_agent(u8 *buffer, u32 buf_len)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	int ret = 0;

	msg = aq_dash_reply_create();
	if (msg == NULL) {
		ret = -ENOMEM;
		goto error_exit;
	}

	hdr = genlmsg_put(msg, 0, 0, &aq_dash_nl_family, NLMSG_DONE, AQ_DASH_EVENT);
	if (hdr == NULL) {
		ret = -ENOMEM;
		goto error_exit;
	}

	if (aq_dash_reply_add_attr(msg, AQ_DASH_ATTR_MSG_DATA,
				   buf_len, buffer) == false) {
		ret = -ENOMEM;
		goto error_exit;
	}

	genlmsg_end(msg, hdr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && \
     RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2)
	genlmsg_multicast(msg, 0, AQ_DASH_EVENT_GROUP, GFP_KERNEL);
#else
	genlmsg_multicast(&aq_dash_nl_family, msg, 0, AQ_DASH_EVENT_GROUP, GFP_KERNEL);
#endif

	return ret;

error_exit:
	if (hdr)
		genlmsg_cancel(msg, hdr);
	if (msg)
		nlmsg_free(msg);

	return ret;
}

static int aq_dash_read_events(struct aq_hw_s *self,
			       struct aq_dash_event_buffer *dash_buf,
			       u16 *len)
{
	struct aq_dash_request req;
	int ret = 0;
	u16 req_buf_len;
	u8 *resp_ptr = NULL;
	u32 msg_id;

	req_buf_len = sizeof(req);

	req.msg_id = AQ_DASH_READ_REQUEST;
	req.power_state = 0;
	req.size = req_buf_len;

	ret = aq_dash_get_data(self, (u8 *)&req, &req_buf_len, &resp_ptr);
	if (ret < 0)
		goto error_exit;

	if (!resp_ptr) {
		ret = -ENOMEM;
		goto error_exit;
	}

	msg_id = ((struct aq_dash_request *)resp_ptr)->msg_id;

	if (msg_id != AQ_DASH_READ_REQUEST) {
		ret = -EINVAL;
		goto error_exit;
	}

	if (req_buf_len > *len) {
		ret = -EINVAL;
		goto error_exit;
	}

	*len = req_buf_len;
	memcpy(dash_buf->data, resp_ptr, req_buf_len);

error_exit:
	kfree(resp_ptr);
	return ret;
}

static bool aq_dash_is_4x_fw(struct aq_nic_s *self)
{
	uint32_t fw_ver;

	fw_ver = self->aq_hw_ops->hw_get_fw_version(self->aq_hw);

	if ((fw_ver >> 24) != 4)
		return false;

	return true;
}

/* will be triggered after 2*Hz timer interval */
int aq_dash_process_events(struct aq_nic_s *self)
{
	struct aq_dash_event_buffer *dash_req = NULL;
	struct aq_dash_event dash_event;
	u32 buf_size, offset = 0;
	int ret = 0;

	if (!ATL_HW_IS_CHIP_FEATURE(self->aq_hw, ATLANTIC) ||
		!aq_dash_is_4x_fw(self))
		goto error_exit;

	offset = offsetof(struct aq_dash_event, data);
	buf_size = sizeof(dash_event) - offset;
	dash_req = (struct aq_dash_event_buffer *)dash_event.data;

	ret = aq_dash_read_events(self->aq_hw, dash_req, (u16 *)&buf_size);

	if (ret < 0) {
		printk(KERN_ERR "FW: couldn't read DASH request\n");
		goto error_exit;
	}

	dash_event.size = buf_size;

	//Indicate AqDashAgent
	ret = aq_dash_indicate_agent((u8 *)&dash_event, buf_size + offset);
	if (ret != 0) {
		printk(KERN_ERR "FW: failed to send event to AqDashAgent\n");
		goto error_exit;
	}

error_exit:
	return ret;
}

static int aq_dash_check_fwreq_attributes(struct genl_info *info)
{
	int ret = 0;

	if (!info->attrs[AQ_DASH_ATTR_CMD_ID]) {
		printk(KERN_ERR "Missing FWREQ_CMD_ID attribute\n");
		ret = -EINVAL;
		goto error_exit;
	}

	if (!info->attrs[AQ_DASH_ATTR_MSG_DATA]) {
		printk(KERN_ERR "Missing FWREQ_MSG_DATA attribute\n");
		ret = -EINVAL;
		goto error_exit;
	}

	if (!info->attrs[AQ_DASH_ATTR_MSG_DATA_LEN]) {
		printk(KERN_ERR "Missing FWREQ_MSG_DATA_LEN attribute\n");
		ret = -EINVAL;
		goto error_exit;
	}

error_exit:
	return ret;
}

static int doit_dash_cfg_fwreq(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *ndev = NULL;
	struct aq_nic_s *aq_nic = NULL;
	struct aq_hw_s *hw = NULL;
	enum aq_dash_msg_id msg_id;
	u8 *dash_cfg = NULL;
	u16 msg_size;
	int ret = 0;
	u8 *resp_ptr = NULL;

	ndev = aq_dash_get_ndev_or_null(info, AQ_DASH_ATTR_IFNAME);
	if (ndev == NULL)
		return -EOPNOTSUPP;

	aq_nic = netdev_priv(ndev);
	hw = aq_nic->aq_hw;

	/* verify the FWREQ attributes */
	if (aq_dash_check_fwreq_attributes(info))
		goto error_exit;

	msg_id = *(u32 *)nla_data(info->attrs[AQ_DASH_ATTR_CMD_ID]);
	msg_size = *(u32 *)nla_data(info->attrs[AQ_DASH_ATTR_MSG_DATA_LEN]);
	dash_cfg = (u8 *)nla_data(info->attrs[AQ_DASH_ATTR_MSG_DATA]);

	switch(msg_id) {
	case AQ_DASH_SEND_DATA:
		ret = aq_dash_send_data(hw, dash_cfg, msg_size);
		if (ret < 0)
			printk(KERN_ERR "Failed to configure DASH\n");

		break;
	case AQ_DASH_GET_DATA:
		ret = aq_dash_get_data(hw, dash_cfg, &msg_size, &resp_ptr);
		if (ret < 0) {
			printk(KERN_ERR "Failed to get DASH configurations\n");
			break;
		}

		/* Send data to user */
		if (resp_ptr != NULL)
			ret = aq_dash_send_to_user(info, resp_ptr, msg_size);

		break;
	default:
		printk(KERN_ERR "Invalid DASH message ID, %d\n", msg_id);
		ret = -EINVAL;
	}

error_exit:
	kfree(resp_ptr);
	dev_put(ndev);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && \
		RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2)
static int aq_dash_pre_doit(struct genl_ops *ops, struct sk_buff *skb,
			      struct genl_info *info)
#else
static int aq_dash_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
			      struct genl_info *info)
#endif
{
	printk(KERN_INFO "Inside %s function\n", __func__);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && \
     RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0)
#define AQ_DASH_NL_OP_POLICY(op_policy) .policy = op_policy
#else
#define AQ_DASH_NL_OP_POLICY(op_policy)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && \
     RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2)
static struct genl_ops aq_dash_nl_ops[] = {
#else
static const struct genl_ops aq_dash_nl_ops[] = {
#endif
	{ .cmd	= AQ_DASH_CMD_FWREQ,
	  .doit	= doit_dash_cfg_fwreq,
	  AQ_DASH_NL_OP_POLICY(aq_dash_nl_policy)
	},
};

static struct genl_family aq_dash_nl_family = {
	.module = THIS_MODULE,
	.name = AQ_DASH_GENL_NAME,
	.version = 1,
	.maxattr = AQ_DASH_ATTR_MAX,
	.netnsok = false,
	.pre_doit = aq_dash_pre_doit,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || \
     RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)
	.ops = aq_dash_nl_ops,
	.n_ops = ARRAY_SIZE(aq_dash_nl_ops),
	.mcgrps = aq_dash_groups,
	.n_mcgrps = ARRAY_SIZE(aq_dash_groups),
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.policy = aq_dash_nl_policy,
#endif
};

/* Register generic netlink family upon module initialization */
int aq_dash_nl_init(void)
{
	int ret = 0;

	ret = genl_register_family(&aq_dash_nl_family);

	if (ret != 0) {
		printk(KERN_ERR "Netlink registration failed\n");
		goto init_failure;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && \
     RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2)
	ret = genl_register_ops(&aq_dash_nl_family, aq_dash_nl_ops);
	if (ret != 0) {
		printk(KERN_ERR "Netlink ops registration failed\n");
		genl_unregister_family(&aq_dash_nl_family);
		goto init_failure;
	}

	ret = genl_register_mc_group(&aq_dash_nl_family, aq_dash_groups);
	if (ret != 0) {
		printk(KERN_ERR "Netlink mc group registration failed\n");
		genl_unregister_ops(&aq_dash_nl_family, aq_dash_nl_ops);
		genl_unregister_family(&aq_dash_nl_family);
		goto init_failure;
	}
#endif

init_failure:
	return ret;
}

void aq_dash_nl_exit(void)
{

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && \
    RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2)
	genl_unregister_mc_group(&aq_dash_nl_family, aq_dash_groups);
	genl_unregister_ops(&aq_dash_nl_family, aq_dash_nl_ops);
#endif
	genl_unregister_family(&aq_dash_nl_family);
}

#include "aq_compat.h"
#ifdef HAS_XDP
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <net/xdp_sock.h>

#include "aq_nic.h"
#include "aq_ring.h"
#include "aq_xdp.h"

int aq_xdp_setup(struct aq_nic_s *aq_nic, struct bpf_prog *prog)
{
	int frame_size = aq_nic->ndev->mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
	struct bpf_prog *old_prog;
	bool need_reset;
	int i;

	// TODO
	/* verify ring attributes are sufficient for XDP *
	for (i = 0; i < self->aq_vecs; ++i) {
		struct aq_vec_s *vec = self->aq_vec[i];
		for (int j = 0; j < vec->)	
	}
	*/

	/* Don't allow frames that span over multiple buffers */
	if (frame_size > AQ_CFG_RX_FRAME_MAX) { // TODO: replace with ring->rx_frame_size
		netdev_err(aq_nic->ndev, "XDP MTU conflict: "
			    "mtu %d frame max %d", frame_size,
			    AQ_CFG_RX_FRAME_MAX);
		return -EINVAL;
	}

	old_prog = xchg(&aq_nic->xdp_prog, prog);
	need_reset = (!!prog != !!old_prog);

	if (need_reset) {
		if (netif_running(aq_nic->ndev)) {
			dev_close(aq_nic->ndev);
			dev_open(aq_nic->ndev, NULL);
		}
	}
	for (i = 0; i < ARRAY_SIZE(aq_nic->aq_ring_rx); i++) {
		if (!aq_nic->aq_ring_rx[i])
			continue;
		(void)xchg(&aq_nic->aq_ring_rx[i]->xdp_prog,
			aq_nic->xdp_prog);
	}

	if (old_prog)
		bpf_prog_put(old_prog);
#if 0
	/* Kick start the NAPI context if there is an AF_XDP socket open
	 * on that queue id. This so that receiving will start.
	 */
	if (need_reset && prog)
		for (i = 0; i < aq_nic->num_rx_queues; i++)
			if (aq_nic->xdp_ring[i]->xsk_umem)
				(void)ixgbe_xsk_wakeup(aq_nic->netdev, i,
						       XDP_WAKEUP_RX);
#endif
	#if 0
	struct aq_pf *pf = nic->back;
	struct bpf_prog *old_prog;


	if (!aq_enabled_xdp_nic(nic) && !prog)
		return 0;

	/* When turning XDP on->off/off->on we reset and rebuild the rings. */
	need_reset = (aq_enabled_xdp_nic(nic) != !!prog);

	if (need_reset)
		aq_prep_for_reset(pf, true);

	old_prog = xchg(&nic->xdp_prog, prog);

	if (need_reset)
		aq_reset_and_rebuild(pf, true, true);

	for (i = 0; i < nic->num_queue_pairs; i++)
		WRITE_ONCE(nic->rx_rings[i]->xdp_prog, nic->xdp_prog);

	if (old_prog)
		bpf_prog_put(old_prog);

	/* Kick start the NAPI context if there is an AF_XDP socket open
	 * on that queue id. This so that receiving will start.
	 */
	if (need_reset && prog)
		for (i = 0; i < nic->num_queue_pairs; i++)
			if (nic->xdp_rings[i]->xsk_umem)
				(void)aq_xsk_wakeup(nic->netdev, i,
						      XDP_WAKEUP_RX);
#endif
	return 0;
}

/* Convert xdp_buff to xdp_frame */
static inline
struct xdp_frame *aq_convert_to_xdp_frame(struct xdp_buff *xdp)
{
	struct xdp_frame *xdp_frame;
	int metasize;
	int headroom;

//	if (xdp->rxq->mem.type == MEM_TYPE_ZERO_COPY)
//		return xdp_convert_zc_to_xdp_frame(xdp);

	/* Assure headroom is available for storing info */
	headroom = xdp->data - xdp->data_hard_start;
	metasize = xdp->data - xdp->data_meta;
	metasize = metasize > 0 ? metasize : 0;

	/* Store info in top of packet */
	xdp_frame = PTR_ALIGN(xdp->data_end, 0x10);

	xdp_frame->data = xdp->data;
	xdp_frame->len  = xdp->data_end - xdp->data;
	xdp_frame->headroom = headroom;
	xdp_frame->metasize = metasize;

	/* rxq only valid until napi_schedule ends, convert to xdp_mem_info */
	xdp_frame->mem = xdp->rxq->mem;

	return xdp_frame;
}

int aq_xdp_xmit_back(struct aq_nic_s *aq_nic, struct xdp_buff *xdp)
{
	struct aq_ring_s *ring;
	struct netdev_queue *nq;
	struct xdp_frame *xdpf;
	int cpu;
	int count;

	xdpf = aq_convert_to_xdp_frame(xdp);
	if (unlikely(!xdpf))
		return -1;

	//nq = netdev_get_tx_queue(pp->dev, txq->id);
	//__netif_tx_lock(nq, cpu);

	count = aq_xdp_xmit(aq_nic->ndev, 1, &xdpf, 0);

	//__netif_tx_unlock(nq);

	return !count;
}


int aq_xdp_execute(struct aq_ring_s *rx_ring, struct xdp_buff *xdp)
{
	struct bpf_prog *xdp_prog = rx_ring->xdp_prog;
	u32 action = XDP_PASS;
	int err = 0;

	rcu_read_lock();

	if (!xdp_prog)
		goto out;

	action = bpf_prog_run_xdp(xdp_prog, xdp);

	switch (action) {
	case XDP_PASS:
	case XDP_DROP:
		break;
	case XDP_REDIRECT: {
		err = xdp_do_redirect(rx_ring->aq_nic->ndev, xdp, xdp_prog);
		if (err) /* force caller to cleanup the packet */
			action = XDP_DROP;
		break;
	}
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->aq_nic->ndev, xdp_prog, action);
		break;
	case XDP_TX:
		err = aq_xdp_xmit_back(rx_ring->aq_nic, xdp);
		if (err) /* force caller to cleanup the packet */
			action = XDP_DROP;
		break;
	default:
		bpf_warn_invalid_xdp_action(action);
		/* force caller to cleanup the packet */
		action = XDP_DROP;
		break;
	}
		
out:
	rcu_read_unlock();
	return action;
}

static int aq_map_xdp(struct aq_ring_s *ring, struct xdp_frame *xdpf)
{
	unsigned int dx = ring->sw_tail;
	struct aq_ring_buff_s *dx_buff;

	dx_buff = &ring->buff_ring[dx];

	dx_buff->flags = 0U;
	dx_buff->pa = dma_map_single(aq_nic_get_dev(ring->aq_nic),
				     xdpf->data,
				     xdpf->len,
				     DMA_TO_DEVICE);

	if (unlikely(dma_mapping_error(aq_nic_get_dev(ring->aq_nic),
				       dx_buff->pa)))
		return -1;

	dx_buff->len = xdpf->len;
	dx_buff->is_eop = dx_buff->is_sop = 1U;
	dx_buff->is_mapped = 1U;
	dx_buff->is_xdp = 1U;
	dx_buff->xdpf = xdpf;

	return 0;
}

int aq_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags)
{
	struct aq_nic_s *aq_nic = netdev_priv(dev);
	struct aq_ring_s *ring;
	int drops = 0;
	int count = 0;
	int cpu;
	int err;

	if (aq_nic->aq_nic_cfg.priv_flags & BIT(AQ_HW_LOOPBACK_DMA_NET))
		return -EBUSY;

	cpu = smp_processor_id() % AQ_CFG_VECS_MAX;
	ring = aq_nic->xdp_prog ?
	       aq_nic->aq_ring_tx[AQ_NIC_CFG_TCVEC2RING(&aq_nic->aq_nic_cfg, 0, cpu)] :
	       NULL;

	if (unlikely(!ring))
		return -ENXIO;

	for (count = 0; count < n; count++) {
		struct xdp_frame *xdpf = frames[count];
		int err;

		if (!aq_ring_avail_dx(ring))
			break;

		err = aq_map_xdp(ring, xdpf);
		if (err) {
			xdp_return_frame_rx_napi(xdpf);
			drops++;
		}
		err = aq_nic->aq_hw_ops->hw_ring_tx_xmit(aq_nic->aq_hw,
			ring, 1);
	}

	// TODO if (unlikely(flags & XDP_XMIT_FLUSH))

	if (!err) {
		ring->stats.tx.packets += n - drops;
		ring->stats.tx.bytes += n - drops; // ??? TODO
	}

	return n - drops;
}

/**
 * aq_xsk_wakeup - Implements the ndo_xsk_wakeup
 * @dev: the netdevice
 * @queue_id: queue id to wake up
 * @flags: ignored in our case since we have Rx and Tx in the same NAPI.
 *
 * Returns <0 for errors, 0 otherwise.
 **/
int aq_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags)
{
	return -1;
}
#endif

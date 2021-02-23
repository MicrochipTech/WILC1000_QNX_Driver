// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#include <sys/slogcodes.h>
#include <stdio.h>
#include <pthread.h>
#include <net/netbyte.h>

#include "wilc_wlan.h"
#include "list.h"
#include "wilc_hif.h"
#include "wilc_wfi_netdevice.h"
#include "wilc_wifi_cfgoperations.h"
#include "wilc_netdev.h"
#include "type_defs.h"

#define __EXT_POSIX1_200112
#define WAKUP_TRAILS_TIMEOUT		(10000)
#define NOT_TCP_ACK			(-1)
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_HLEN	14		/* Total octets in header. */
#define IPPROTO_TCP  6		/* Transmission Control Protocol	*/

static inline bool is_wilc1000(uint32_t id)
{
	return ((id & 0xfffff000) == 0x100000 ? true : false);
}

static inline bool is_wilc3000(uint32_t id)
{
	return ((id & 0xfffff000) == 0x300000 ? true : false);
}


#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)


void acquire_bus(struct wilc_dev *wilc, enum bus_acquire acquire, int source)
{
	pthread_mutex_lock(&wilc->hif_cs);

	if (acquire == WILC_BUS_ACQUIRE_AND_WAKEUP)
		chip_wakeup(wilc, source);
}

void release_bus(struct wilc_dev *wilc, enum bus_release release, int source)
{
	if (release == WILC_BUS_RELEASE_ALLOW_SLEEP)
		chip_allow_sleep(wilc, source);

	pthread_mutex_unlock(&wilc->hif_cs);

}

uint8_t reset_bus(struct wilc_dev *wilc)
{
	uint8_t ret = 0;

	if (wilc->io_type == HIF_SPI)
		return wilc->hif_func->hif_reset(wilc);
	return ret;
}

static void wilc_wlan_txq_remove(struct wilc_dev *wilc, uint8_t q_num,
				 struct txq_entry_t *tqe)
{
	list_del(&tqe->list);
	wilc->txq_entries -= 1;
	wilc->txq[q_num].count--;
}

static struct txq_entry_t *
wilc_wlan_txq_remove_from_head(struct wilc_dev *wilc, uint8_t q_num)
{
	struct txq_entry_t *tqe = NULL;

	pthread_spin_lock(&wilc->txq_spinlock);

	if (!list_empty(&wilc->txq[q_num].txq_head.list)) {
		tqe = list_first_entry(&wilc->txq[q_num].txq_head.list,
				       struct txq_entry_t, list);
		list_del(&tqe->list);
		wilc->txq_entries -= 1;
		wilc->txq[q_num].count--;
	}

	pthread_spin_unlock(&wilc->txq_spinlock);
	return tqe;
}

static void wilc_wlan_txq_add_to_tail(struct wilc_vif *vif, uint8_t q_num,
				      struct txq_entry_t *tqe)
{
	struct wilc_dev *wilc = vif->wilc;

	pthread_spin_lock(&wilc->txq_spinlock);

	list_add_tail(&tqe->list, &wilc->txq[q_num].txq_head.list);
	wilc->txq_entries += 1;
	wilc->txq[q_num].count++;
	PRINT_INFO(TX_DBG, "Number of entries in TxQ = %d\n", wilc->txq_entries);

	pthread_spin_unlock(&wilc->txq_spinlock);

	PRINT_INFO(TX_DBG, "Wake the txq_handling\n");
	//complete(&wilc->txq_event);

	pthread_mutex_lock(&wilc->txq_event_mutex);
	//wilc->txq_event++;
	pthread_cond_signal(&wilc->txq_event);
	pthread_mutex_unlock(&wilc->txq_event_mutex);

}


static void wilc_wlan_txq_add_to_head(struct wilc_vif *vif, uint8_t q_num,
				     struct txq_entry_t *tqe)
{
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] In\n", __func__);
	struct wilc_dev *wilc = vif->wilc;

	pthread_mutex_lock(&wilc->txq_add_to_head_cs);

	pthread_spin_lock(&wilc->txq_spinlock);
	list_add(&tqe->list, &wilc->txq[q_num].txq_head.list);

	wilc->txq_entries += 1;
	wilc->txq[q_num].count++;
	PRINT_INFO(TX_DBG, "Number of entries in TxQ = %d\n", wilc->txq_entries);

	pthread_spin_unlock(&wilc->txq_spinlock);
	pthread_mutex_unlock(&wilc->txq_add_to_head_cs);

	//complete(&wilc->txq_event);

	pthread_mutex_lock(&wilc->txq_event_mutex);
	//wilc->txq_event++;
	pthread_cond_signal(&wilc->txq_event);
	pthread_mutex_unlock(&wilc->txq_event_mutex);

	PRINT_INFO(TX_DBG,"Wake up the txq_handler\n");

}

static inline void add_tcp_session(struct wilc_vif *vif, u32 src_prt,
				  u32 dst_prt, u32 seq)
{
	struct tcp_ack_filter *f = &vif->ack_filter;

	if (f->tcp_session < 2 * MAX_TCP_SESSION) {
		f->ack_session_info[f->tcp_session].seq_num = seq;
		f->ack_session_info[f->tcp_session].bigger_ack_num = 0;
		f->ack_session_info[f->tcp_session].src_port = src_prt;
		f->ack_session_info[f->tcp_session].dst_port = dst_prt;
		f->tcp_session++;
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] TCP Session %d to Ack %d\n", __func__, f->tcp_session, seq);

	}
}

static inline void update_tcp_session(struct wilc_vif *vif, u32 index, u32 ack)
{
	struct tcp_ack_filter *f = &vif->ack_filter;

	if (index < 2 * MAX_TCP_SESSION &&
	    ack > f->ack_session_info[index].bigger_ack_num)
		f->ack_session_info[index].bigger_ack_num = ack;
}

static inline void add_tcp_pending_ack(struct wilc_vif *vif, u32 ack,
				      u32 session_index,
				      struct txq_entry_t *txqe)
{
	struct tcp_ack_filter *f = &vif->ack_filter;
	u32 i = f->pending_base + f->pending_acks_idx;

	if (i < MAX_PENDING_ACKS) {
		f->pending_acks[i].ack_num = ack;
		f->pending_acks[i].txqe = txqe;
		f->pending_acks[i].session_index = session_index;
		txqe->ack_idx = i;
		f->pending_acks_idx++;
	}
}

static inline void tcp_process(struct wilc_vif *vif, struct txq_entry_t *tqe)
{
	void *buffer = tqe->buffer;
	const struct ethhdr *eth_hdr_ptr = buffer;
	int i;
	struct wilc_dev *wilc = vif->wilc;
	struct tcp_ack_filter *f = &vif->ack_filter;
	const struct iphdr *ip_hdr_ptr;
	const struct tcphdr *tcp_hdr_ptr;
	u32 ihl, total_length, data_offset;

	spin_lock_irqsave(&wilc->txq_spinlock, flags);

	if (eth_hdr_ptr->h_proto != htons(ETH_P_IP))
		goto out;

	ip_hdr_ptr = buffer + ETH_HLEN;

	if (ip_hdr_ptr->protocol != IPPROTO_TCP)
		goto out;

	ihl = ip_hdr_ptr->ihl << 2;
	tcp_hdr_ptr = buffer + ETH_HLEN + ihl;
	total_length = ntohs(ip_hdr_ptr->tot_len);

	data_offset = tcp_hdr_ptr->doff << 2;
	if (total_length == (ihl + data_offset)) {
		u32 seq_no, ack_no;

		seq_no = ntohl(tcp_hdr_ptr->seq);
		ack_no = ntohl(tcp_hdr_ptr->ack_seq);
		for (i = 0; i < f->tcp_session; i++) {
			u32 j = f->ack_session_info[i].seq_num;

			if (i < 2 * MAX_TCP_SESSION &&
			    j == seq_no) {
				update_tcp_session(vif, i, ack_no);
				break;
			}
		}
		if (i == f->tcp_session)
			add_tcp_session(vif, 0, 0, seq_no);

		add_tcp_pending_ack(vif, ack_no, i, tqe);
	}

out:
	spin_unlock_irqrestore(&wilc->txq_spinlock, flags);
}

static void wilc_wlan_txq_filter_dup_tcp_ack(struct wilc_vif *vif)
{
	struct wilc_dev *wilc = vif->wilc;
	struct tcp_ack_filter *f = &vif->ack_filter;
	uint32_t i = 0;
	uint32_t dropped = 0;
	pthread_spin_lock(&wilc->txq_spinlock);

	for (i = f->pending_base;
	     i < (f->pending_base + f->pending_acks_idx); i++) {
		uint32_t index;
		uint32_t bigger_ack_num;

		if (i >= MAX_PENDING_ACKS)
			break;

		index = f->pending_acks[i].session_index;

		if (index >= 2 * MAX_TCP_SESSION)
			break;

		bigger_ack_num = f->ack_session_info[index].bigger_ack_num;

		if (f->pending_acks[i].ack_num < bigger_ack_num) {
			struct txq_entry_t *tqe;

			slogf(_SLOGC_NETWORK, _SLOG_ERROR, "[%s] DROP ACK: %u", __func__,  f->pending_acks[i].ack_num);;
			tqe = f->pending_acks[i].txqe;
			if (tqe) {
				wilc_wlan_txq_remove(wilc, tqe->q_num, tqe);
				tqe->status = 1;
				if (tqe->tx_complete_func)
					tqe->tx_complete_func(tqe->priv,
							      tqe->status);
				free(tqe, M_DEVBUF);
				dropped++;
			}
		}
	}
	f->pending_acks_idx = 0;
	f->tcp_session = 0;

	if (f->pending_base == 0)
		f->pending_base = MAX_TCP_SESSION;
	else
		f->pending_base = 0;

	pthread_spin_unlock(&wilc->txq_spinlock);


	struct timespec		ts;
	nsec2timespec( &ts, (uint64_t) 1 * 1000 * 1000);

	while (dropped > 0) {
		pthread_mutex_lock(&wilc->txq_event_mutex);
		if (pthread_cond_wait(&wilc->txq_event, &wilc->txq_event_mutex) != EOK){
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] completion timedout \n", __func__);
		}
		pthread_mutex_unlock(&wilc->txq_event_mutex);

		dropped--;
	}
}


void wilc_enable_tcp_ack_filter(struct wilc_vif *vif, bool value)
{
	vif->ack_filter.enabled = value;
}

static int wilc_wlan_txq_add_cfg_pkt(struct wilc_vif *vif, uint8_t *buffer,
				     uint32_t buffer_size)
{
	struct txq_entry_t *tqe;
	struct wilc_dev *wilc = vif->wilc;
        int i;

	PRINT_INFO(TX_DBG, "Adding config packet ...\n");

	if (wilc->quit) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Return due to clear function\n");
		//complete(&wilc->cfg_event);
		pthread_sleepon_lock();
		wilc->cfg_event++;
		pthread_sleepon_signal(&wilc->cfg_event);
		pthread_sleepon_unlock();
		return 0;
	}

	if (!(wilc->initialized)) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"wilc not initialized\n");
		//complete(&wilc->cfg_event);
		pthread_sleepon_lock();
		wilc->cfg_event++;
		pthread_sleepon_signal(&wilc->cfg_event);
		pthread_sleepon_unlock();
		return 0;
	}
	tqe = create_ptr(sizeof(*tqe));
	PRINT_D(TX_DBG, "[%s], tqe = %p\n", __func__, tqe);
	if (!tqe) {
		//complete(&wilc->cfg_event);
		pthread_sleepon_lock();
		wilc->cfg_event++;
		pthread_sleepon_signal(&wilc->cfg_event);
		pthread_sleepon_unlock();
		return 0;
	}
	tqe->type = WILC_CFG_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = NULL;
	tqe->priv = NULL;
	tqe->q_num = AC_VO_Q;
	tqe->ack_idx = NOT_TCP_ACK;
	tqe->vif = vif;

	PRINT_INFO(TX_DBG, "[%s]buffer_size = %d\n", __func__, tqe->buffer_size);

	PRINT_INFO(TX_DBG, "Adding the config packet at the Queue tail\n");

	wilc_wlan_txq_add_to_head(vif, AC_VO_Q, tqe);

	return 1;
}

static void ac_q_limit(struct wilc_dev *wilc, u8 ac, u16 *q_limit)
{
	static u8 buffer[AC_BUFFER_SIZE];
	static u16 end_index;
	static bool initialized;
	static u16 cnt[NQUEUES];
	u8 factors[NQUEUES] = {1, 1, 1, 1};
	static u16 sum;
	u16 i;
	//unsigned long flags;

	spin_lock_irqsave(&wilc->txq_spinlock, flags);
	if (!initialized) {
		for (i = 0; i < AC_BUFFER_SIZE; i++)
			buffer[i] = i % NQUEUES;

		for (i = 0; i < NQUEUES; i++) {
			cnt[i] = AC_BUFFER_SIZE * factors[i] / NQUEUES;
			sum += cnt[i];
		}
		end_index = AC_BUFFER_SIZE - 1;
		initialized = 1;
	}

	cnt[buffer[end_index]] -= factors[buffer[end_index]];
	cnt[ac] += factors[ac];
	sum += (factors[ac] - factors[buffer[end_index]]);

	buffer[end_index] = ac;
	if (end_index > 0)
		end_index--;
	else
		end_index = AC_BUFFER_SIZE - 1;

	for (i = 0; i < NQUEUES; i++) {
		if (!sum)
			q_limit[i] = 1;
		else
			q_limit[i] = (cnt[i] * FLOW_CTRL_UP_THRESHLD / sum) + 1;
	}
	spin_unlock_irqrestore(&wilc->txq_spinlock, flags);
}



static inline u8 ac_classify(struct wilc_dev *wilc, struct txq_entry_t *tqe)
{
	u8 *eth_hdr_ptr;
	u8 *buffer = tqe->buffer;
	u8 ac;
	u16 h_proto;
	//unsigned long flags;

	spin_lock_irqsave(&wilc->txq_spinlock, flags);

	eth_hdr_ptr = &buffer[0];
	h_proto = ntohs(*((u16 *)&eth_hdr_ptr[12]));
	if (h_proto == ETH_P_IP) {
		u8 *ip_hdr_ptr;
		u32 IHL, DSCP;
		(void)IHL; //FIXME

		ip_hdr_ptr = &buffer[ETHERNET_HDR_LEN];
		IHL = (ip_hdr_ptr[0] & 0xf) << 2;
		DSCP = (ip_hdr_ptr[1] & 0xfc);

		switch (DSCP) {
		case 0x20:
		case 0x40:
		case 0x08:
			ac = AC_BK_Q;
			break;
		case 0x80:
		case 0xA0:
		case 0x28:
			ac = AC_VI_Q;
			break;
		case 0xC0:
		case 0xd0:
		case 0xE0:
		case 0x88:
		case 0xB8:
			ac = AC_VO_Q;
			break;
		default:
			ac = AC_BE_Q;
			break;
		}
	} else {
		ac  = AC_BE_Q;
	}

	tqe->q_num = ac;
	spin_unlock_irqrestore(&wilc->txq_spinlock, flags);

	return ac;
}

static inline int ac_balance(u8 *count, u8 *ratio)
{
	u8 i, max_count = 0;

	if (!count || !ratio)
		return -1;

	for (i = 0; i < NQUEUES; i++)
		if (count[i] > max_count)
			max_count = count[i];

	for (i = 0; i < NQUEUES; i++)
		ratio[i] = max_count - count[i];

	return 0;
}

static inline void ac_pkt_count(u32 reg, u8 *pkt_count)
{
	pkt_count[AC_BK_Q] = (reg & 0x000000fa) >> BK_AC_COUNT_POS;
	pkt_count[AC_BE_Q] = (reg & 0x0000fe00) >> BE_AC_COUNT_POS;
	pkt_count[AC_VI_Q] = (reg & 0x00fe0000) >> VI_AC_COUNT_POS;
	pkt_count[AC_VO_Q] = (reg & 0xfe000000) >> VO_AC_COUNT_POS;
}

static inline u8 ac_change(struct wilc_dev *wilc, u8 *ac)
{
	do {
		if (wilc->txq[*ac].acm == 0)
			return 0;
		(*ac)++;
	} while (*ac < NQUEUES);
	return 1;
}

static inline void ac_acm_bit(struct wilc_dev *wilc, u32 reg)
{
	wilc->txq[AC_BK_Q].acm = (reg & 0x00000002) >> BK_AC_ACM_STAT_POS;
	wilc->txq[AC_BE_Q].acm = (reg & 0x00000100) >> BE_AC_ACM_STAT_POS;
	wilc->txq[AC_VI_Q].acm = (reg & 0x00010000) >> VI_AC_ACM_STAT_POS;
	wilc->txq[AC_VO_Q].acm = (reg & 0x01000000) >> VO_AC_ACM_STAT_POS;
}

int txq_add_net_pkt(struct wilc_vif *vif, void *priv, u8 *buffer,
			      u32 buffer_size,
			      void (*tx_complete_fn)(void *, int))
{
	struct txq_entry_t *tqe;
	struct wilc_dev *wilc;
	u8 q_num;
	u16 q_limit[NQUEUES] = {0, 0, 0, 0};

	if (!vif) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] vif is NULL\n", __func__);
		return -1;
	}

	wilc = vif->wilc;

	if (wilc->quit) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] drv is quitting, return from net_pkt\n", __func__);
		tx_complete_fn(priv, 0);
		return 0;
	}

	if (!(wilc->initialized)) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] not_init, return from net_pkt\n", __func__);
		tx_complete_fn(priv, 0);
		return 0;
	}

	tqe = (struct txq_entry_t *) create_ptr(sizeof(*tqe));

	if (!tqe) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] malloc failed, return from net_pkt\n", __func__);
		tx_complete_fn(priv, 0);
		return 0;
	}
	tqe->type = WILC_NET_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = tx_complete_fn;
	tqe->priv = priv;
	tqe->vif = vif;

	q_num = ac_classify(wilc, tqe);
	if (ac_change(wilc, &q_num)) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] No suitable non-ACM queue\n", __func__);
		kfree(tqe);
		return 0;
	}
	ac_q_limit(wilc, q_num, q_limit);

	if ((q_num == AC_VO_Q && wilc->txq[q_num].count <= q_limit[AC_VO_Q]) ||
	    (q_num == AC_VI_Q && wilc->txq[q_num].count <= q_limit[AC_VI_Q]) ||
	    (q_num == AC_BE_Q && wilc->txq[q_num].count <= q_limit[AC_BE_Q]) ||
	    (q_num == AC_BK_Q && wilc->txq[q_num].count <= q_limit[AC_BK_Q])) {

		PRINT_INFO(TX_DBG, "[%s] Adding mgmt packet at the Queue tail\n", __func__);

		tqe->ack_idx = NOT_TCP_ACK;
		if (vif->ack_filter.enabled)
			tcp_process(vif, tqe);
		wilc_wlan_txq_add_to_tail(vif, q_num, tqe);
	} else {
		tqe->status = 0;
		if (tqe->tx_complete_func)
			tqe->tx_complete_func(tqe->priv, tqe->status);
		free_ptr(tqe);
	}

	return wilc->txq_entries;
}

int txq_add_mgmt_pkt(struct wilc_vif *vif, void *priv, u8 *buffer,
			       u32 buffer_size,
			       void (*tx_complete_fn)(void *, int))
{
	struct txq_entry_t *tqe;
	struct wilc_dev *wilc;

	wilc = vif->wilc;

	if (wilc->quit) {
		PRINT_INFO(TX_DBG, "drv is quitting\n");
		tx_complete_fn(priv, 0);
		return 0;
	}

	if (!(wilc->initialized)) {
		PRINT_INFO(TX_DBG, "wilc not_init\n");
		tx_complete_fn(priv, 0);
		return 0;
	}
	tqe = (struct txq_entry_t *) create_ptr(sizeof(*tqe));

	if (!tqe) {
		PRINT_INFO(TX_DBG, "Queue malloc failed\n");
		tx_complete_fn(priv, 0);
		return 0;
	}
	tqe->type = WILC_MGMT_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = tx_complete_fn;
	tqe->priv = priv;
	tqe->q_num = AC_BE_Q;
	tqe->ack_idx = NOT_TCP_ACK;
	tqe->vif = vif;

	PRINT_INFO(TX_DBG, "Adding Mgmt packet to Queue tail\n");
	wilc_wlan_txq_add_to_tail(vif, AC_VO_Q, tqe);
	return 1;
}

static struct txq_entry_t *txq_get_first(struct wilc_dev *wilc, uint8_t q_num)
{
	struct txq_entry_t *tqe = NULL;

	pthread_spin_lock(&wilc->txq_spinlock);
	if (!list_empty(&wilc->txq[q_num].txq_head.list))
		tqe = list_first_entry(&wilc->txq[q_num].txq_head.list,
				       struct txq_entry_t, list);

	pthread_spin_unlock(&wilc->txq_spinlock);
	return tqe;
}

static struct txq_entry_t *txq_get_next(struct wilc_dev *wilc,
					struct txq_entry_t *tqe, uint8_t q_num)
{
	pthread_spin_lock(&wilc->txq_spinlock);

	if (!list_is_last(&tqe->list, &wilc->txq[q_num].txq_head.list))
		tqe = list_next_entry(tqe, list);
	else
		tqe = NULL;

	pthread_spin_unlock(&wilc->txq_spinlock);

	return tqe;
}


static void rxq_add(struct wilc_dev *wilc, struct rxq_entry_t *rqe)
{
	if (wilc->quit)
		return;

	pthread_mutex_lock(&wilc->rxq_cs);
	list_add_tail(&rqe->list, &wilc->rxq_head.list);
	pthread_mutex_unlock(&wilc->rxq_cs);
}

static struct rxq_entry_t *rxq_remove(struct wilc_dev *wilc)
{
	struct rxq_entry_t *rqe = NULL;
	pthread_mutex_lock(&wilc->rxq_cs);
	if (!list_empty(&wilc->rxq_head.list)) {
		rqe = list_first_entry(&wilc->rxq_head.list, struct rxq_entry_t,
				       list);
		list_del(&rqe->list);
	}
	pthread_mutex_unlock(&wilc->rxq_cs);

	return rqe;
}

int chip_allow_sleep_wilc1000(struct wilc_dev *wilc, int source)
{
	uint32_t reg = 0;
	const struct wilc_hif_func *hif_func = wilc->hif_func;
	uint32_t wakeup_reg, wakeup_bit;
	uint32_t to_host_from_fw_reg, to_host_from_fw_bit;
	uint32_t from_host_to_fw_reg, from_host_to_fw_bit;
	uint32_t trials = 100;
	int ret;

	if (wilc->io_type == HIF_SDIO ||
		wilc->io_type == HIF_SDIO_GPIO_IRQ) {
		wakeup_reg = 0xf0;
		wakeup_bit = BIT(0);
		from_host_to_fw_reg = 0xfa;
		from_host_to_fw_bit = BIT(0);
		to_host_from_fw_reg = 0xfc;
		to_host_from_fw_bit = BIT(0);
	} else {
		wakeup_reg = 0x1;
		wakeup_bit = BIT(1);
		from_host_to_fw_reg = 0x0b;
		from_host_to_fw_bit = BIT(0);
		to_host_from_fw_reg = 0xfc;
		to_host_from_fw_bit = BIT(0);
	}

	while (trials--) {
		ret = hif_func->hif_read_reg(wilc, to_host_from_fw_reg, &reg);
		if (!ret)
			return -EIO;

		if ((reg & to_host_from_fw_bit) == 0)
			break;
	}

	if (!trials)
		printf("FW not responding\n");

	/* Clear bit 1 */
	ret = hif_func->hif_read_reg(wilc, wakeup_reg, &reg);

	if (!ret)
		return -EIO;
	if (reg & wakeup_bit) {
		reg &= ~wakeup_bit;
		ret = hif_func->hif_write_reg(wilc, wakeup_reg, reg);

		if (!ret)
			return -EIO;
	}

	ret = hif_func->hif_read_reg(wilc, from_host_to_fw_reg, &reg);

	if (!ret)
		return -EIO;
	if (reg & from_host_to_fw_bit) {
		reg &= ~from_host_to_fw_bit;
		ret = hif_func->hif_write_reg(wilc, from_host_to_fw_reg, reg);
		if (!ret)
			return -EIO;
	}

	return 0;
}

void chip_allow_sleep(struct wilc_dev *wilc, int source)
{
	int ret = 0;
	(void)ret; //TODO

	ret = chip_allow_sleep_wilc1000(wilc, source);

}


void chip_wakeup_wilc1000(struct wilc_dev *wilc, int source)
{
	uint32_t ret = 0;
	uint32_t clk_status_val = 0, trials = 0;
	uint32_t wakeup_reg, wakeup_bit;
	uint32_t clk_status_reg, clk_status_bit;
	uint32_t to_host_from_fw_reg, to_host_from_fw_bit;
	uint32_t from_host_to_fw_reg, from_host_to_fw_bit;
	const struct wilc_hif_func *hif_func = wilc->hif_func;
	(void)to_host_from_fw_reg; //FIXME
	(void)to_host_from_fw_bit; //FIXME

	if (wilc->io_type == HIF_SDIO ||
		wilc->io_type == HIF_SDIO_GPIO_IRQ) {
		wakeup_reg = 0xf0;
		clk_status_reg = 0xf1;
		wakeup_bit = BIT(0);
		clk_status_bit = BIT(0);
		from_host_to_fw_reg = 0xfa;
		from_host_to_fw_bit = BIT(0);
		to_host_from_fw_reg = 0xfc;
		to_host_from_fw_bit = BIT(0);
	} else {
		wakeup_reg = 0x1;
		clk_status_reg = 0x0f;
		wakeup_bit = BIT(1);
		clk_status_bit = BIT(2);
		from_host_to_fw_reg = 0x0b;
		from_host_to_fw_bit = BIT(0);
		to_host_from_fw_reg = 0xfc;
		to_host_from_fw_bit = BIT(0);
	}

	/*USE bit 0 to indicate host wakeup*/
	ret = hif_func->hif_write_reg(wilc, from_host_to_fw_reg,
					  from_host_to_fw_bit);
	if (!ret)
		goto _fail_;

	/* Set bit 1 */
	ret = hif_func->hif_write_reg(wilc, wakeup_reg,
					  wakeup_bit);

	if (!ret)
		goto _fail_;

	do {
		ret = hif_func->hif_read_reg(wilc, clk_status_reg,
					     &clk_status_val);
		if (!ret) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Bus error (5).%d %x\n", __func__, ret, clk_status_val);
			goto _fail_;
		}
		if (clk_status_val & clk_status_bit)
			break;

		//nm_bsp_sleep(2);
		trials++;
		if (trials > WAKUP_TRAILS_TIMEOUT) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Failed to wakup the chip\n", __func__);
			ret = -1;
			goto _fail_;
		}
	} while (1);

	if (wilc_get_chipid(wilc, false) < 0x1002b0) {
		uint32_t val32;
		/* Enable PALDO back right after wakeup */
		hif_func->hif_read_reg(wilc, 0x1e1c, &val32);
		val32 |= BIT(6);
		hif_func->hif_write_reg(wilc, 0x1e1c, val32);

		hif_func->hif_read_reg(wilc, 0x1e9c, &val32);
		val32 |= BIT(6);
		hif_func->hif_write_reg(wilc, 0x1e9c, val32);
	}
	/*workaround sometimes spi fail to read clock regs after reading
	 * writing clockless registers
	 */

	reset_bus(wilc);

_fail_:
	return;
}



void chip_wakeup(struct wilc_dev *wilc, int source)
{
	chip_wakeup_wilc1000(wilc, source);
}


void host_wakeup_notify(struct wilc_dev *wilc, int source)
{
	acquire_bus(wilc, WILC_BUS_ACQUIRE_ONLY, source);
	if (wilc->chip == WILC_1000)
		wilc->hif_func->hif_write_reg(wilc, 0x10b0, 1);
	else
		wilc->hif_func->hif_write_reg(wilc, 0x10c0, 1);
	release_bus(wilc, WILC_BUS_RELEASE_ONLY, source);
}

void host_sleep_notify(struct wilc_dev *wilc, int source)
{
	acquire_bus(wilc, WILC_BUS_ACQUIRE_ONLY, source);
	if (wilc->chip == WILC_1000)
		wilc->hif_func->hif_write_reg(wilc, 0x10ac, 1);
	else
		wilc->hif_func->hif_write_reg(wilc, 0x10bc, 1);
	release_bus(wilc, WILC_BUS_RELEASE_ONLY, source);
}


static uint8_t ac_fw_count[NQUEUES] = {0, 0, 0, 0};
int wilc_wlan_handle_txq(struct wilc_dev *wilc, uint32_t *txq_count)
{
	int i, entries = 0;
	uint8_t k, ac;
	uint32_t sum;
	uint32_t reg;
	uint8_t ac_desired_ratio[NQUEUES] = {0, 0, 0, 0};
	uint8_t ac_preserve_ratio[NQUEUES] = {1, 1, 1, 1};
	uint8_t *num_pkts_to_add;
	uint8_t vmm_entries_ac[WILC_VMM_TBL_SIZE];
	uint8_t *txb;
	uint32_t offset = 0;
	bool max_size_over = 0, ac_exist = 0;
	int vmm_sz = 0;
	struct txq_entry_t *tqe_q[NQUEUES];
	int ret = 0;
	int counter;
	int timeout;
	uint32_t vmm_table[WILC_VMM_TBL_SIZE];
	uint8_t ac_pkt_num_to_chip[NQUEUES] = {0, 0, 0, 0};
	struct wilc_vif *vif;
	const struct wilc_hif_func *func;
	int srcu_idx;

	PRINT_D(TX_DBG, "[%s] In\n",__func__);

	txb = wilc->tx_buffer;
	if (!wilc->txq_entries) {
		*txq_count = 0;
		return 0;
	}

	if (wilc->quit)
		goto out;

	if (ac_balance(ac_fw_count, ac_desired_ratio))
		return -1;

	pthread_mutex_lock(&wilc->txq_add_to_head_cs);

	srcu_idx = srcu_read_lock(&wilc->srcu);
	list_for_each_entry(vif, &wilc->vif_list, list)
		wilc_wlan_txq_filter_dup_tcp_ack(vif);

	srcu_read_unlock(&wilc->srcu, srcu_idx);

	for (ac = 0; ac < NQUEUES; ac++)
		tqe_q[ac] = txq_get_first(wilc, ac);

	i = 0;
	sum = 0;
	max_size_over = 0;
	num_pkts_to_add = ac_desired_ratio;
	do {
		ac_exist = 0;
		for (ac = 0; (ac < NQUEUES) && (!max_size_over); ac++) {
			if (!tqe_q[ac])
				continue;
			vif = tqe_q[ac]->vif;
			ac_exist = 1;
			for (k = 0; (k < num_pkts_to_add[ac]) &&
				    (!max_size_over) && tqe_q[ac]; k++) {
				if (i >= (WILC_VMM_TBL_SIZE - 1)) {
					max_size_over = 1;
					break;
				}

				if (tqe_q[ac]->type == WILC_CFG_PKT)
				{
					vmm_sz = ETH_CONFIG_PKT_HDR_OFFSET;
				}
				else if (tqe_q[ac]->type == WILC_NET_PKT)
				{
					vmm_sz = ETH_ETHERNET_HDR_OFFSET;
				}
				else
				{
					vmm_sz = HOST_HDR_OFFSET;
				}

				vmm_sz += tqe_q[ac]->buffer_size;

				if (vmm_sz & 0x3)
					vmm_sz = (vmm_sz + 4) & ~0x3;

				if ((sum + vmm_sz) > WILC_TX_BUFF_SIZE) {
					max_size_over = 1;
					break;
				}

				vmm_table[i] = vmm_sz / 4;

				if (tqe_q[ac]->type == WILC_CFG_PKT) {
					vmm_table[i] |= BIT(10);
					PRINT_INFO(TX_DBG, "[%s] VMMTable entry changed for CFG packet = %d\n",__func__, vmm_table[i]);
				}
				//cpu_to_le32s(&vmm_table[i]);
				vmm_entries_ac[i] = ac;

				i++;
				sum += vmm_sz;
				tqe_q[ac] = txq_get_next(wilc, tqe_q[ac], ac);
			}
		}
		num_pkts_to_add = ac_preserve_ratio;
	} while (!max_size_over && ac_exist);

	if (i == 0)
		goto out;
	vmm_table[i] = 0x0;

	acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, DEV_WIFI);
	counter = 0;
	func = wilc->hif_func;
	do {
		ret = func->hif_read_reg(wilc, WILC_HOST_TX_CTRL, &reg);
		if (!ret) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail read reg vmm_tbl_entry..\n", __func__);

			break;
		}
		if ((reg & 0x1) == 0) {
			ac_pkt_count(reg, ac_fw_count);
			ac_acm_bit(wilc, reg);
			break;
		}

		counter++;
		if (counter > 200) {
			counter = 0;
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Looping in tx ctrl , force quit\n", __func__);

			ret = func->hif_write_reg(wilc, WILC_HOST_TX_CTRL, 0);
			break;
		}
	} while (!wilc->quit);

	if (!ret)
		goto out_release_bus;

	timeout = 200;
	do {
		ret = func->hif_block_tx(wilc,
					 VMM_TBL_RX_SHADOW_BASE,
					 (uint8_t *)vmm_table,
					 ((i + 1) * 4));

		if (!ret) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] ERR block TX of VMM table.\n", __func__);
			break;
		}

		if (wilc->chip == WILC_1000) {
			ret = wilc->hif_func->hif_write_reg(wilc,
							    WILC_HOST_VMM_CTL,
							    0x2);
			if (!ret) {
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail write reg host_vmm_ctl..\n", __func__);
				break;
			}

			do {
				ret = func->hif_read_reg(wilc,
						      WILC_HOST_VMM_CTL,
						      &reg);
				if (!ret)
					break;
				if ((reg >> 2) & 0x1) {
					entries = ((reg >> 3) & 0x3f);
					break;
				}
			} while (--timeout);
		} else {
			ret = func->hif_write_reg(wilc,
					      WILC_HOST_VMM_CTL,
					      0);
			if (!ret) {
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail write reg host_vmm_ctl..\n", __func__);
				break;
			}
			/* interrupt firmware */
			ret = func->hif_write_reg(wilc,
					      WILC_INTERRUPT_CORTUS_0,
					      1);
			if (!ret) {
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail write reg WILC_INTERRUPT_CORTUS_0..\n", __func__);
				break;
			}

			do {
				ret = func->hif_read_reg(wilc,
						      WILC_INTERRUPT_CORTUS_0,
						      &reg);
				if (!ret) {
					slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail read reg WILC_INTERRUPT_CORTUS_0..\n", __func__);
					break;
				}
				if (reg == 0) {
					// Get the entries

					ret = func->hif_read_reg(wilc,
							      WILC_HOST_VMM_CTL,
							      &reg);
					if (!ret) {
						slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail read reg host_vmm_ctl..\n", __func__);
						break;
					}
					entries = ((reg >> 3) & 0x3f);
					break;
				}
			} while (--timeout);
		}
		if (timeout <= 0) {
			ret = func->hif_write_reg(wilc, WILC_HOST_VMM_CTL, 0x0);
			break;
		}

		if (!ret)
			break;

		if (entries == 0) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] no buffer in the chip (reg: %08x), retry later [[ %d, %x ]]\n", __func__, reg, i, vmm_table[i-1]);
			fprintf(stderr, "[%s] no buffer in the chip (reg: %08x), retry later [[ %d, %x ]]\n", __func__, reg, i, vmm_table[i-1]);
			ret = func->hif_read_reg(wilc, WILC_HOST_TX_CTRL, &reg);
			if (!ret) {
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail read reg WILC_HOST_TX_CTRL..\n", __func__);
				break;
			}
			reg &= ~BIT(0);
			ret = func->hif_write_reg(wilc, WILC_HOST_TX_CTRL, reg);
			if (!ret) {
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail write reg WILC_HOST_TX_CTRL..\n", __func__);
				break;
			}
			break;
		}
		break;
	} while (1);

	if (!ret)
		goto out_release_bus;

	if (entries == 0) {
		ret = -ENOBUFS;
		goto out_release_bus;
	}

	release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
	offset = 0;
	i = 0;
	do {
		struct txq_entry_t *tqe;
		uint32_t header, buffer_offset;

		tqe = wilc_wlan_txq_remove_from_head(wilc, vmm_entries_ac[i]);
		ac_pkt_num_to_chip[vmm_entries_ac[i]]++;
		if (!tqe)
			break;

		if (vmm_table[i] == 0)
			break;

		vif = tqe->vif;
		//le32_to_cpus(&vmm_table[i]);
		vmm_sz = (vmm_table[i] & 0x3ff);
		vmm_sz *= 4;
		header = (tqe->type << 31) |
			 (tqe->buffer_size << 15) |
			 vmm_sz;
		if (tqe->type == WILC_MGMT_PKT)
			header |= BIT(30);
		else
			header &= ~BIT(30);

		//cpu_to_le32s(&header);
		memcpy(&txb[offset], &header, 4);
		if (tqe->type == WILC_CFG_PKT) {
			buffer_offset = ETH_CONFIG_PKT_HDR_OFFSET;
		} else if (tqe->type == WILC_NET_PKT) {
			u8 *bssid = tqe->vif->bssid;
			int prio = tqe->q_num;

			buffer_offset = ETH_ETHERNET_HDR_OFFSET;
			memcpy(&txb[offset + 4], &prio, sizeof(prio));
			memcpy(&txb[offset + 8], bssid, 6);

		} else {
			buffer_offset = HOST_HDR_OFFSET;
		}


		memcpy(&txb[offset + buffer_offset],
		       tqe->buffer, tqe->buffer_size);
		offset += vmm_sz;

		i++;
		tqe->status = 1;
		if (tqe->tx_complete_func)
			tqe->tx_complete_func(tqe->priv,
					      tqe->status);

		if (tqe->ack_idx != NOT_TCP_ACK &&
		    tqe->ack_idx < MAX_PENDING_ACKS)
			vif->ack_filter.pending_acks[tqe->ack_idx].txqe = NULL;

		free_ptr(tqe);

	} while (--entries);
	for (i = 0; i < NQUEUES; i++)
		ac_fw_count[i] += ac_pkt_num_to_chip[i];

	acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, DEV_WIFI);

	ret = func->hif_clear_int_ext(wilc, ENABLE_TX_VMM);
	if (!ret) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail start tx VMM ...\n", __func__);
		goto out_release_bus;
	}

	ret = func->hif_block_tx_ext(wilc, 0, txb, offset);
	if (!ret)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail block tx ext...\n", __func__);

out_release_bus:
	release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);


out:
	pthread_mutex_unlock(&wilc->txq_add_to_head_cs);

	*txq_count = wilc->txq_entries;
	if (ret == 1)
		cfg_packet_timeout = 0;

	return ret;
}


static void wilc_wlan_handle_rx_buff(struct wilc_dev *wilc, uint8_t *buffer, int size)
{
	int offset = 0;
	uint32_t header;
	uint32_t pkt_len, pkt_offset, tp_len;
	int is_cfg_packet;
	uint8_t *buff_ptr;

	do {
		buff_ptr = buffer + offset;
		//header = get_unaligned_le32(buff_ptr);
		memcpy(&header, buff_ptr, 4);

		is_cfg_packet = (header >> 31) & 0x1;
		pkt_offset = (header >> 22) & 0x1ff;
		tp_len = (header >> 11) & 0x7ff;
		pkt_len = header & 0x7ff;

		if (pkt_len == 0 || tp_len == 0) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: Data corrupted %d, %d\n", __func__, pkt_len, tp_len);
			break;
		}
		//slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: is_cfg_packet = %d, pkt_offset = %d, tp_len = %d, pkt_len = %d\n", __func__, is_cfg_packet, pkt_offset, tp_len, pkt_len);
		if (is_cfg_packet) {
			struct wilc_cfg_rsp rsp;

			buff_ptr += pkt_offset;

			cfg_indicate_rx(wilc, buff_ptr, pkt_len,
					&rsp);
			if (rsp.type == WILC_CFG_RSP) {
				if (wilc->cfg_seq_no == rsp.seq_no)
				{
					pthread_sleepon_lock();
					wilc->cfg_event++;
					pthread_sleepon_signal(&wilc->cfg_event);
					///complete(&wilc->cfg_event);
					pthread_sleepon_unlock();
				}

			} else if (rsp.type == WILC_CFG_RSP_STATUS) {
				wilc_mac_indicate(wilc);
			}
		} else if (pkt_offset & IS_MANAGMEMENT) {
			buff_ptr += HOST_HDR_OFFSET;
			wilc_wfi_mgmt_rx(wilc, buff_ptr, pkt_len);
		} else if (pkt_offset & IS_MON_PKT) {
			/* packet received on monitor interface */
			buff_ptr += HOST_HDR_OFFSET;

			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: Monitor pkt received, do not handle\n", __func__);

		} else if (pkt_len > 0) {

			struct wilc_vif *vif;
			int srcu_idx;

			srcu_idx = srcu_read_lock(&wilc->srcu);

			vif = wilc_get_wl_to_vif(wilc); //FIXME: validating vif
			wilc_frmw_to_host(vif, buff_ptr, pkt_len,
					  pkt_offset, PKT_STATUS_NEW);
			srcu_read_unlock(&wilc->srcu, srcu_idx);
		}

		offset += tp_len;
		if (offset >= size)
			break;
	} while (1);

}

static void wilc_wlan_handle_rxq(struct wilc_dev *wilc)
{
	int size;
	uint8_t *buffer;
	struct rxq_entry_t *rqe;
	PRINT_D(RX_DBG, "[%s] In\n", __func__);

	do {
		if (wilc->quit) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s Quitting. Exit handle RX queue\n", __func__);
			pthread_sleepon_lock();
			wilc->cfg_event++;
			pthread_sleepon_signal(&wilc->cfg_event);
			///complete(&wilc->cfg_event);
			pthread_sleepon_unlock();
			break;
		}
		rqe = rxq_remove(wilc);
		if (!rqe)
			break;

		buffer = rqe->buffer;
		size = rqe->buffer_size;

		wilc_wlan_handle_rx_buff(wilc, buffer, size);
		free_ptr(rqe);
	} while (1);

}
static void wilc_unknown_isr_ext(struct wilc_dev *wilc)
{
	wilc->hif_func->hif_clear_int_ext(wilc, 0);
}

static void wilc_wlan_handle_isr_ext(struct wilc_dev *wilc, uint32_t int_status)
{
	uint32_t offset = wilc->rx_buffer_offset;
	uint8_t *buffer = NULL;
	uint32_t size;
	uint32_t retries = 0;
	int ret = 0;
	struct rxq_entry_t *rqe;

	size = (int_status & 0x7fff) << 2;
	PRINT_D(INT_DBG, "%s: size = %d\n", __func__, size);

	while (!size && retries < 10) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: RX Size equal zero Trying to read it again\n", __func__);
		wilc->hif_func->hif_read_size(wilc, &size);
		size = (size & 0x7fff) << 2;
		retries++;
	}

	if (size <= 0)
		return;

	if (WILC_RX_BUFF_SIZE - offset < size)
	{
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: rx_buf is larger than WILC_RX_BUFF_SIZE\n", __func__);
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: Clear rx_buf\n", __func__);
		offset = 0;
	}

	buffer = &wilc->rx_buffer[offset];

	wilc->hif_func->hif_clear_int_ext(wilc, DATA_INT_CLR | ENABLE_RX_VMM);

	ret = wilc->hif_func->hif_block_rx_ext(wilc, 0, buffer, size);
	if (!ret) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: fail block rx\n", __func__);
		return;
	}

	offset += size;

	wilc->rx_buffer_offset = offset;

	rqe = (struct rxq_entry_t *) create_ptr(sizeof(*rqe));


	if (!rqe)
	{
		return;
	}

	rqe->buffer = buffer;
	rqe->buffer_size = size;
	rxq_add(wilc, rqe);
	wilc_wlan_handle_rxq(wilc);
}

void wilc_handle_isr(struct wilc_dev *wilc)
{
	uint32_t int_status;

	acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, DEV_WIFI);
	wilc->hif_func->hif_read_int(wilc, &int_status);

	if (int_status & DATA_INT_EXT)
		wilc_wlan_handle_isr_ext(wilc, int_status);

	if (!(int_status & (ALL_INT_EXT))) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s,>> UNKNOWN_INTERRUPT - 0x%08x\n", __func__, int_status);

		wilc_unknown_isr_ext(wilc);
	}

	release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
}


int wilc_wlan_firmware_download(struct wilc_dev *wilc, FILE *fp)
{
	uint32_t offset;
	uint32_t addr, size, size2, blksz;
	uint8_t *dma_buffer;
	int ret = 0;
	uint32_t reg = 0;

	blksz = 4096;
	dma_buffer = (uint8_t *) create_ptr(blksz);

	if (!dma_buffer) {
		printf("Can't allocate buffer for fw download IO error\n");
		return -1;
	}

	// read file data to buffer
	fseek(fp, 0, SEEK_END);
	long buffer_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);  /* same as rewind(f); */

	char *fw_buf = (char *) create_ptr(buffer_size + 1);
	fread(fw_buf, 1, buffer_size, fp);

	offset = 0;

	acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, 0);


	/* Assert CPU reset */
	wilc->hif_func->hif_read_reg(wilc, WILC_GLB_RESET_0, &reg);

	reg &= ~(1ul << 10);


	ret = wilc->hif_func->hif_write_reg(wilc, WILC_GLB_RESET_0, reg);
	wilc->hif_func->hif_read_reg(wilc, WILC_GLB_RESET_0, &reg);

	if ((reg & (1ul << 10)) != 0)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Failed to reset Wifi CPU\n", __func__);

	release_bus(wilc, WILC_BUS_RELEASE_ONLY, 0);

	do {
		memcpy(&addr, &fw_buf[offset], 4);
		memcpy(&size, &fw_buf[offset + 4], 4);
		///le32_to_cpus(&addr);
		///le32_to_cpus(&size);

		acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, 0);
		offset += 8;
		while (((int)size) && (offset < buffer_size)) {
			if (size <= blksz)
				size2 = size;
			else
				size2 = blksz;

			memcpy(dma_buffer, &fw_buf[offset], size2);
			wilc->hif_func->hif_block_tx(wilc, addr, dma_buffer, size2);
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] send block_tx... addr=0x%x, offset = %d, size2=%d, data1=0x%x, data2=0x%x\n", __func__, addr, offset, size2, fw_buf[offset], fw_buf[offset+size2-1]);


			if (!ret)
				break;


			addr += size2;
			offset += size2;
			size -= size2;
		}
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, 0);

		if (!ret) {
			ret = -EIO;
			printf("Bus error\n");
			goto fail;
		}
		printf("Offset = %d\n", offset);

	} while (offset < buffer_size);

fail:

	free_ptr(dma_buffer);
	free_ptr(fw_buf);
	return (ret < 0) ? ret : 0;
}

int wilc_wlan_start(struct wilc_dev *wilc)
{
	uint32_t reg = 0;
	int ret;

	if (wilc->io_type == HIF_SDIO ||
	    wilc->io_type == HIF_SDIO_GPIO_IRQ)
		reg |= BIT(3);
	else if (wilc->io_type == HIF_SPI)
		reg = 1;

	acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, DEV_WIFI);
	ret = wilc->hif_func->hif_write_reg(wilc, WILC_VMM_CORE_CFG, reg);
	if (!ret) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail write reg vmm_core_cfg...\n", __func__);
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}
	reg = 0;
	if (wilc->io_type == HIF_SDIO_GPIO_IRQ)
		reg |= WILC_HAVE_SDIO_IRQ_GPIO;

	if (wilc->chip == WILC_3000)
		reg |= WILC_HAVE_SLEEP_CLK_SRC_RTC;


	ret = wilc->hif_func->hif_write_reg(wilc, WILC_GP_REG_1, reg);
	if (!ret) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] fail write WILC_GP_REG_1...\n", __func__);
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	wilc->hif_func->hif_read_reg(wilc, WILC_GLB_RESET_0, &reg);
	if ((reg & BIT(10)) == BIT(10)) {
		reg &= ~BIT(10);
		wilc->hif_func->hif_write_reg(wilc, WILC_GLB_RESET_0, reg);
		wilc->hif_func->hif_read_reg(wilc, WILC_GLB_RESET_0, &reg);
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] read WILC_GLB_RESET_0 2... reg=0x%x\n", __func__, reg);
	}

	reg |= BIT(10);
	ret = wilc->hif_func->hif_write_reg(wilc, WILC_GLB_RESET_0, reg);
	wilc->hif_func->hif_read_reg(wilc, WILC_GLB_RESET_0, &reg);

	if (ret >= 0)
		wilc->initialized = 1;
	else
		wilc->initialized = 0;
	release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);

	return (ret < 0) ? ret : 0;
}


int wilc_wlan_stop(struct wilc_dev *wilc, struct wilc_vif *vif)
{
	u32 reg = 0;
	int ret;

	acquire_bus(wilc, WILC_BUS_ACQUIRE_AND_WAKEUP, DEV_WIFI);

	/* Clear Wifi mode*/
	ret = wilc->hif_func->hif_read_reg(wilc, GLOBAL_MODE_CONTROL, &reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while reading reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	reg &= ~BIT(0);
	ret = wilc->hif_func->hif_write_reg(wilc, GLOBAL_MODE_CONTROL, reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while writing reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	/* Configure the power sequencer to ignore WIFI sleep signal on making
	 * chip sleep decision
	 */
	ret = wilc->hif_func->hif_read_reg(wilc, PWR_SEQ_MISC_CTRL, &reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while reading reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	reg &= ~BIT(28);
	ret = wilc->hif_func->hif_write_reg(wilc, PWR_SEQ_MISC_CTRL, reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while writing reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	ret = wilc->hif_func->hif_read_reg(wilc, WILC_GP_REG_0, &reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while reading reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	ret = wilc->hif_func->hif_write_reg(wilc, WILC_GP_REG_0,
					(reg | WILC_ABORT_REQ_BIT));
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while writing reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	ret = wilc->hif_func->hif_read_reg(wilc, WILC_FW_HOST_COMM, &reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while reading reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}
	reg = BIT(0);

	ret = wilc->hif_func->hif_write_reg(wilc, WILC_FW_HOST_COMM, reg);
	if (!ret) {
		PRINT_ER(vif->ndev, "Error while writing reg\n");
		release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);
		return -EIO;
	}

	release_bus(wilc, WILC_BUS_RELEASE_ALLOW_SLEEP, DEV_WIFI);

	return 0;
}


void wilc_wlan_cleanup(struct wilc_vif *vif)
{
	struct txq_entry_t *tqe;
	struct rxq_entry_t *rqe;
	u8 ac;
	//struct wilc_vif *vif = netdev_priv(dev);
	struct wilc_dev *wilc = vif->wilc;

	wilc->quit = 1;
	for (ac = 0; ac < NQUEUES; ac++) {
		do {
			tqe = wilc_wlan_txq_remove_from_head(wilc, ac);
			if (!tqe)
				break;
			if (tqe->tx_complete_func)
				tqe->tx_complete_func(tqe->priv, 0);
			kfree(tqe);
		} while (1);
	}

	do {
		rqe = rxq_remove(wilc);
		if (!rqe)
			break;
		kfree(rqe);
	} while (1);

	kfree(wilc->rx_buffer);
	wilc->rx_buffer = NULL;
	kfree(wilc->tx_buffer);
	wilc->tx_buffer = NULL;
}

static int wilc_wlan_cfg_commit(struct wilc_vif *vif, int type,
		uint32_t drv_handler)
{
	struct wilc_dev *wilc = vif->wilc;
	struct wilc_cfg_frame *cfg = &wilc->cfg_frame;
	int t_len = wilc->cfg_frame_offset + sizeof(struct wilc_cfg_cmd_hdr);

	if (type == WILC_CFG_SET)
		cfg->hdr.cmd_type = 'W';
	else
		cfg->hdr.cmd_type = 'Q';

	cfg->hdr.seq_no = wilc->cfg_seq_no % 256;
	//cfg->hdr.total_len = (cpu_to_le16) t_len;
	cfg->hdr.total_len = (uint16_t) t_len;
	//cfg->hdr.driver_handler = cpu_to_le32(drv_handler);
	cfg->hdr.driver_handler = (uint32_t) drv_handler;
	wilc->cfg_seq_no = cfg->hdr.seq_no;

	if (!wilc_wlan_txq_add_cfg_pkt(vif, (uint8_t *)&cfg->hdr, t_len))
		return -1;

	return 0;
}

int cfg_set(struct wilc_vif *vif, int start, uint16_t wid, uint8_t *buffer, uint32_t buffer_size, int commit, uint32_t drv_handler)
{
	uint32_t offset;
	int ret_size;
	struct wilc_dev *wilc = vif->wilc;

	pthread_mutex_lock(&wilc->cfg_cmd_lock);

	if (start)
		wilc->cfg_frame_offset = 0;

	offset = wilc->cfg_frame_offset;
	ret_size = cfg_set_wid(vif, wilc->cfg_frame.frame, offset,
					 wid, buffer, buffer_size);
	offset += ret_size;
	wilc->cfg_frame_offset = offset;

	if (!commit) {
		pthread_mutex_unlock(&wilc->cfg_cmd_lock);
		return ret_size;
	}

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[WILC]PACKET Commit with sequence number%d\n", wilc->cfg_seq_no);


	if (wilc_wlan_cfg_commit(vif, WILC_CFG_SET, drv_handler))
		ret_size = 0;

	uint64_t tmo = (uint64_t) 3 * 1000 * 1000 * 1000;
	pthread_sleepon_lock();
	if (pthread_sleepon_timedwait(&wilc->cfg_event, tmo) != EOK) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Timed out \n", __func__);
		ret_size = 0;
	}
	pthread_sleepon_unlock();

	wilc->cfg_frame_offset = 0;
	wilc->cfg_seq_no += 1;
	pthread_mutex_unlock(&wilc->cfg_cmd_lock);

	return ret_size;
}


int cfg_get(struct wilc_vif *vif, int start, uint16_t wid, int commit,
		uint32_t drv_handler)
{
	uint32_t offset;
	int ret_size;
	struct wilc_dev *wilc = vif->wilc;

	pthread_mutex_lock(&wilc->cfg_cmd_lock);

	if (start)
		wilc->cfg_frame_offset = 0;

	offset = wilc->cfg_frame_offset;
	ret_size = cfg_get_wid(wilc->cfg_frame.frame, offset, wid);
	offset += ret_size;
	wilc->cfg_frame_offset = offset;

	if (!commit) {
		pthread_mutex_unlock(&wilc->cfg_cmd_lock);
		return ret_size;
	}

	if (wilc_wlan_cfg_commit(vif, WILC_CFG_QUERY, drv_handler))
		ret_size = 0;

	uint64_t tmo = (uint64_t) 3 * 1000 * 1000 * 1000;
	pthread_sleepon_lock();
	if (pthread_sleepon_timedwait(&wilc->cfg_event, tmo) != EOK) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Timed out \n", __func__);
		ret_size = 0;
	}
	pthread_sleepon_unlock();

	wilc->cfg_frame_offset = 0;
	wilc->cfg_seq_no += 1;
	pthread_mutex_unlock(&wilc->cfg_cmd_lock);

	return ret_size;
}

unsigned int cfg_packet_timeout;

int wilc_send_config_pkt(struct wilc_vif *vif, uint8_t mode, struct wid *wids,
		uint32_t count)
{
	int i;
	int ret = 0;
	uint32_t drv = wilc_get_vif_idx(vif);

	if (wait_for_recovery) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Host interface is suspended\n");
		while (wait_for_recovery)
			usleep(300000);
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Host interface is resumed\n");

	}

	if (mode == WILC_GET_CFG) {
		for (i = 0; i < count; i++) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Sending CFG packet [%d][%d]\n", !i, (i == count - 1));

			if (!cfg_get(vif, !i, wids[i].id, (i == count - 1),
				     drv)) {
				ret = -ETIMEDOUT;
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Get Timed out\n");
				break;
			}
		}
		for (i = 0; i < count; i++) {
			wids[i].size = cfg_get_val(vif->wilc, wids[i].id,
							     (u8 *)wids[i].val,
							     wids[i].size);
		}
	} else if (mode == WILC_SET_CFG) {
		for (i = 0; i < count; i++) {
			PRINT_INFO(TX_DBG, "Sending config SET PACKET WID:%x\n", wids[i].id);

			if (!cfg_set(vif, !i, wids[i].id, (u8 *)wids[i].val,
				     wids[i].size, (i == count - 1), drv)) {
				ret = -ETIMEDOUT;
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Set Timed out\n");
				break;
			}
		}
	}
	cfg_packet_timeout = (ret < 0) ? cfg_packet_timeout + 1 : 0;
	return ret;
}


uint32_t init_chip(struct wilc_dev *wilc)
{
	uint32_t reg, ret = 0;

	ret = wilc->hif_func->hif_read_reg(wilc, 0x1118, &reg);

	if (!ret) {

		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"fail read reg 0x1118\n");
		goto end;
	}

	reg |= BIT(0);
	ret = wilc->hif_func->hif_write_reg(wilc, 0x1118, reg);
	if (!ret) {

		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"fail write reg 0x1118\n");
		goto end;
	}
	ret = wilc->hif_func->hif_write_reg(wilc, 0xc0000, 0x71);
	if (!ret) {

		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"fail write reg 0xc0000 ...\n");
		goto end;
	}

	if (wilc->chip == WILC_3000) {
		ret = wilc->hif_func->hif_read_reg(wilc, 0x207ac, &reg);
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Bootrom sts = %x\n", reg);
		ret = wilc->hif_func->hif_write_reg(wilc, 0x4f0000,
						    0x71);
		if (!ret) {

			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"fail write reg 0x4f0000 ...\n");
			goto end;
		}
	}

end:


	return ret;
}

uint32_t wilc_get_chipid(struct wilc_dev *wilc, bool update)
{
	static uint32_t chipid;
	int ret;
	uint32_t tempchipid = 0;

	(void)ret; //TODO
	if (chipid == 0 || update) {

		if (!is_wilc3000(tempchipid)) {
			ret = wilc->hif_func->hif_read_reg(wilc, 0x1000,
						     &tempchipid);
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log4, tempchipid = 0x%x\n", __func__, tempchipid);
			if (!is_wilc1000(tempchipid)) {
				chipid = 0;
				return chipid;
			}
			if (tempchipid < 0x1003a0) {
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"WILC1002 isn't suported %x\n", chipid);
				chipid = 0;
				return chipid;
			}
		}
		chipid = tempchipid;
	}


	return chipid;
}

int wilc_wlan_init(struct wilc_vif *vif)
{
	int ret = 0;
	struct wilc_dev *wilc;

	wilc = vif->wilc;

	wilc->quit = 0;

	PRINT_INFO(INIT_DBG, "Initializing WILC_Wlan\n");

	if (!wilc->hif_func->hif_is_init(wilc)) {
		acquire_bus(wilc, WILC_BUS_ACQUIRE_ONLY, DEV_WIFI);
		if (!wilc->hif_func->hif_init(wilc, false)) {
			ret = -EIO;
			release_bus(wilc, WILC_BUS_RELEASE_ONLY, DEV_WIFI);
			goto fail;
		}
		release_bus(wilc, WILC_BUS_RELEASE_ONLY, DEV_WIFI);
	}

	if (!wilc->tx_buffer)
		wilc->tx_buffer = (uint8_t *) create_ptr(WILC_TX_BUFF_SIZE);

	if (!wilc->tx_buffer) {
		ret = -ENOBUFS;
		PRINT_ER(vif->ndev, "Can't allocate Tx Buffer");
		goto fail;
	}

	if (!wilc->rx_buffer)
		wilc->rx_buffer = (uint8_t *) create_ptr(WILC_RX_BUFF_SIZE);
	PRINT_D(TX_DBG, "g_wlan.rx_buffer =%p\n", wilc->rx_buffer);
	if (!wilc->rx_buffer) {
		ret = -ENOBUFS;
		PRINT_ER(vif->ndev, "Can't allocate Rx Buffer");
		goto fail;
	}

	if (!init_chip(wilc)) {
		ret = -EIO;
		goto fail;
	}

	return 1;

fail:

	kfree(wilc->rx_buffer);
	wilc->rx_buffer = NULL;
	kfree(wilc->tx_buffer);
	wilc->tx_buffer = NULL;

	return ret;
}



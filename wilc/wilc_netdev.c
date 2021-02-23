// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#include <sys/slogcodes.h>
#include "wilc_main.h"
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <pthread.h>
#include <io-pkt/quiesce.h>
#include <io-pkt/nw_thread.h>
#include <sys-nto/bpfilter.h>
#include "wilc_wfi_netdevice.h"
#include "workqueue.h"
#include "etherdevice.h"
#include "wilc_netdev.h"
#include "wilc_wifi_cfgoperations.h"

int debug_running;
int recovery_on;
int wait_for_recovery;


void wilc_mac_indicate(struct wilc_dev *wilc)
{
	int8_t status;
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: In\n", __func__);
	cfg_get_val(wilc, WID_STATUS, (uint8_t *)&status, 1);
	if (wilc->mac_status == WILC_MAC_STATUS_INIT) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: log2\n", __func__);
		wilc->mac_status = status;

		pthread_sleepon_lock();
		wilc->sync_event++;
		pthread_sleepon_signal(&wilc->sync_event);
		///complete(&wilc->sync_event);
		pthread_sleepon_unlock();

	} else {
		wilc->mac_status = status;
	}
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: Out\n", __func__);
}


void wilc_frmw_to_host(struct wilc_vif *vif, u8 *buff, u32 size,
		       u32 pkt_offset, u8 status)
{
	unsigned int frame_len = 0;
	unsigned char *buff_to_send = NULL;
	struct wilc_priv *priv;
	u8 null_bssid[ETH_ALEN] = {0};
	struct itimerspec setting;
	struct pkt_buf		*pkt;
	struct wilc_dev *wilc;

	PRINT_D(RX_DBG, "[%s] In, size = %d pkt_offset = %d \n", __func__, size, pkt_offset);

	buff += pkt_offset;
	priv = &vif->priv;
	wilc = vif->wilc;

	frame_len = size;
	buff_to_send = buff;

	//fprintf(stderr,"[%s] In, size = %d buff_to_send = 0x%x 0x%x, status = %d vif->iftype = %d\n", __func__, size, buff_to_send[12], buff_to_send[13], status, vif->iftype);
	if (status == PKT_STATUS_NEW && buff_to_send[12] == 0x88 &&
	   buff_to_send[13] == 0x8e &&
	   (vif->iftype == WILC_STATION_MODE ||
		vif->iftype == WILC_CLIENT_MODE) &&
	   ether_addr_equal_unaligned(priv->associated_bss, null_bssid)) {

		fprintf(stderr, "[%s] Buffer EAPOL packet\n", __func__);
		if (!priv->buffered_eap) {
			priv->buffered_eap = create_ptr(sizeof(struct
											wilc_buffered_eap));
			if (priv->buffered_eap) {
				priv->buffered_eap->buff = NULL;
				priv->buffered_eap->size = 0;
				priv->buffered_eap->pkt_offset = 0;
			} else {
				PRINT_ER(vif->ndev,
					 "failed to alloc buffered_eap\n");
				return;
			}
		} else {
			free_ptr(priv->buffered_eap->buff);
		}
		priv->buffered_eap->buff = create_ptr(size + pkt_offset);
		priv->buffered_eap->size = size;
		priv->buffered_eap->pkt_offset = pkt_offset;
		memcpy(priv->buffered_eap->buff, buff -
			   pkt_offset, size + pkt_offset);

		setting.it_value.tv_sec = 0;
		setting.it_value.tv_nsec = 10000000;
		setting.it_interval.tv_sec = 0;
		setting.it_interval.tv_nsec = 0;
		fprintf(stderr, "[%s] Buffer EAPOL packet log2\n", __func__);
		timer_settime (priv->eap_buff_timer, 0, &setting, 0);
		return;
	}


	pkt = create_ptr(sizeof(struct pkt_buf));
	pkt->size = size;
	pkt->buf = create_ptr(size);
	if (pkt->buf == NULL)
		slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] cannot allocate memory\n", __func__);

	
	memset(pkt->buf, 0, size);
	memcpy(pkt->buf, buff, size);

		pthread_mutex_lock(&wilc->rx_mutex);

		list_add_tail(&pkt->list,&wilc->rx_q.list);

	pthread_mutex_unlock(&wilc->rx_mutex);

	if (size == 0) {
		PRINT_ER(vif->ndev,
			 "Discard sending packet with len = %d\n", size);
		return;
	}

	vif->netstats.rx_packets++;
	vif->netstats.rx_bytes += frame_len;

}

void free_eap_buff_params(void *vp)
{
	struct wilc_priv *priv;

	priv = (struct wilc_priv *)vp;

	if (priv->buffered_eap) {
		free_ptr(priv->buffered_eap->buff);
		priv->buffered_eap->buff = NULL;

		free_ptr(priv->buffered_eap);
		priv->buffered_eap = NULL;
	}
}

void eap_buff_timeout(union sigval sig)
{
	u8 null_bssid[ETH_ALEN] = {0};
	u8 *assoc_bss;
	static u8 timeout = 5;
	struct itimerspec setting;
	int status = -1;
	struct wilc_vif *vif = (struct wilc_vif *)sig.sival_ptr;
	struct wilc_priv *priv = &vif->priv;

	assoc_bss = priv->associated_bss;
	if (!(memcmp(assoc_bss, null_bssid, ETH_ALEN)) && (timeout-- > 0)) {
		setting.it_value.tv_sec = 0;
		setting.it_value.tv_nsec = 10000000;
		timer_settime (priv->eap_buff_timer, 0, &setting, 0);
		return;
	}

	timeout = 5;

	status = wilc_send_buffered_eap(vif, wilc_frmw_to_host,
					free_eap_buff_params,
					priv->buffered_eap->buff,
					priv->buffered_eap->size,
					priv->buffered_eap->pkt_offset,
					(void *)priv);
	if (status)
		PRINT_ER(vif->ndev, "Failed so send buffered eap\n");

}

void wilc_wlan_set_bssid(struct wilc_vif *vif, u8 *bssid, u8 mode)
{
	struct wilc_dev *wilc = vif->wilc;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&wilc->srcu);

	list_for_each_entry(vif, &wilc->vif_list, list) {
		if (bssid)
			ether_addr_copy(vif->bssid, bssid);
		else
			eth_zero_addr(vif->bssid);
		PRINT_INFO(GENERIC_DBG,
			   "set bssid [%pM]\n", vif->bssid);

		vif->iftype = mode;
	}
	srcu_read_unlock(&wilc->srcu, srcu_idx);
}

#define TX_BACKOFF_WEIGHT_INCR_STEP (1)
#define TX_BACKOFF_WEIGHT_DECR_STEP (1)
#define TX_BACKOFF_WEIGHT_MAX (0)
#define TX_BACKOFF_WEIGHT_MIN (0)
#define TX_BCKOFF_WGHT_MS (1)

static int quiescing = 0;
static int quiesce_die = 0;


static int quiescing_irq_event = 0;
static int quiesce_die_irq_event = 0;

void get_irq_event_handler(void *data)
{
	struct wilc_dev *wilc = (struct wilc_dev *) data;

	while (1)
	{
		sdio_event_get(wilc->sdio, 1);
	}

}

static int wilc_intr_thread_create(struct wilc_dev *wilc)
{
	pthread_attr_t		attr;
	struct sched_param	param;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] In\n", __func__);
	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_RR);



	param.sched_priority = 21;
	pthread_attr_setschedparam(&attr, &param);
	pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, 32768);

	/* Create SDIO event handler */
	if (pthread_create(&wilc->irq_tid, &attr, (void *)get_irq_event_handler, wilc)) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"sdio_start:  Unable to create event handler\n");
		return -1;
	}

	return 0;
}


static void thread_quiesce (void *arg, int die)
{
	struct wilc_dev  *dev = (struct wilc_dev *)arg;
	(void)dev; //TODO

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] In\n", __func__);
    quiescing = 1;
    quiesce_die = die;
}

static int pkt_rx_task_init_fn (void *arg)
{
    struct nw_work_thread	*wtp;
    struct wilc_dev 		*dev = (struct wilc_dev *)arg;

    pthread_setname_np(0, "Tx task thread");

    wtp = WTP;

    wtp->quiesce_callout = thread_quiesce;
    wtp->quiesce_arg = dev;

    return EOK;
}

static int pkt_rx_task(void *vp)
{
	struct mbuf			*m;
	struct ifnet		*ifp;
	struct wilc_dev *wl = vp;
	struct pkt_buf *pkt;
	int j;

	ifp = &wl->sc_ec.ec_if;
	//ifp = wl->sc_ic.ic_ifp;

	while (1) {
		if (quiescing) {
			if (quiesce_die) {
			/*
			 * Thread will terminate on calling
			 * quiesce_block(), clean up here
			 * if required.
			 */
			}
			quiesce_block(quiesce_die);
			quiescing = 0;
		}



		pthread_mutex_lock(&wl->rx_mutex);

		if (!list_empty(&wl->rx_q.list))
		{
			pkt = list_first_entry(&wl->rx_q.list, struct pkt_buf, list);
			//slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] pkt->size = %d, \n", __func__, pkt->size);

			m = m_getcl_wtp(M_DONTWAIT, MT_DATA, M_PKTHDR, WTP);

			if (!m) {
				ifp->if_ierrors++;  // for ifconfig -v
				continue;
				//return 1;
			}

			m->m_pkthdr.len = pkt->size;
			m->m_len = pkt->size;

			memcpy(m->m_hdr.mh_data, pkt->buf, m->m_pkthdr.len);

			///m_copyback(m, 0, pkt->size, pkt->buf);

			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] size = %d, mh_len = %d \n", __func__, m->m_pkthdr.len, m->m_hdr.mh_len);

			if (m->m_hdr.mh_len > 40)
			{
				for (j = 0; j<3; j++)
					slogf(_SLOGC_NETWORK, _SLOG_ERROR,"buf = 0x%x  0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x \n", m->m_hdr.mh_data[9*j], m->m_hdr.mh_data[9*j+1], m->m_hdr.mh_data[9*j+2], m->m_hdr.mh_data[9*j+3], m->m_hdr.mh_data[9*j+4], m->m_hdr.mh_data[9*j+5], m->m_hdr.mh_data[9*j+6], m->m_hdr.mh_data[9*j+7], m->m_hdr.mh_data[9*j+8]);
			}
			// ip_input() needs this
			m->m_pkthdr.rcvif = ifp;

			ifp->if_ipackets++; // for ifconfig -v

#if NBPFILTER > 0
			if (ifp->if_bpf)
				bpf_mtap(ifp->if_bpf, m);
#endif

			(*ifp->if_input)(ifp, m);

			list_del(&pkt->list);
			free_ptr(pkt->buf);
			free_ptr(pkt);
			pthread_mutex_unlock(&wl->rx_mutex);
		} else {
			pthread_mutex_unlock(&wl->rx_mutex);
		}

		usleep(10);
	}
}

static int wilc_txq_task(void *vp)
{
	int ret;
	uint32_t txq_count;
	int backoff_weight = TX_BACKOFF_WEIGHT_MIN;
	struct wilc_dev *wl = vp;

	pthread_sleepon_lock();
	wl->txq_thread_started++;
	pthread_sleepon_signal(&wl->txq_thread_started);
	pthread_sleepon_unlock();

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	while (1) {
		pthread_mutex_lock(&wl->txq_event_mutex);
		PRINT_INFO(TX_DBG, "txq_task Taking a nap\n");

		if (pthread_cond_wait(&wl->txq_event, &wl->txq_event_mutex) != EOK){
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Wait fail \n", __func__);
		}

		PRINT_INFO(TX_DBG, "txq_task Who waked me up\n");

		if (wl->close) {

			pthread_sleepon_unlock();
			pthread_sleepon_lock();
			wl->txq_thread_started++;
			pthread_sleepon_signal(&wl->txq_thread_started);
			pthread_sleepon_unlock();

			//cancellation point
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			usleep(100);

			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"TX thread stopped\n");
			break;
		}
		PRINT_INFO(TX_DBG, "handle the tx packet\n");
		do {
			ret = wilc_wlan_handle_txq(wl, &txq_count);
			if (txq_count < FLOW_CTRL_LOW_THRESHLD) {
				struct wilc_vif *ifc;
				int srcu_idx;

				srcu_idx = srcu_read_lock(&wl->srcu);
				PRINT_INFO(TX_DBG, "Waking up queue\n");
				list_for_each_entry(ifc, &wl->vif_list,
							list) {

				}
				srcu_read_unlock(&wl->srcu, srcu_idx);

			}

			if (ret == -ENOBUFS) {

				do {
			/* Back off from sending packets for some time.
			 * schedule_timeout will allow RX task to run and free
			 * buffers. Setting state to TASK_INTERRUPTIBLE will
			 * put the thread back to CPU running queue when it's
			 * signaled even if 'timeout' isn't elapsed. This gives
			 * faster chance for reserved SK buffers to be freed
			 */

				} while (/*timeout*/0);

				backoff_weight += TX_BACKOFF_WEIGHT_INCR_STEP;
				if (backoff_weight > TX_BACKOFF_WEIGHT_MAX)
					backoff_weight = TX_BACKOFF_WEIGHT_MAX;
			} else if (backoff_weight > TX_BACKOFF_WEIGHT_MIN) {
				backoff_weight -= TX_BACKOFF_WEIGHT_DECR_STEP;
				if (backoff_weight < TX_BACKOFF_WEIGHT_MIN)
					backoff_weight = TX_BACKOFF_WEIGHT_MIN;
			}
		} while (ret == -ENOBUFS && !wl->close);

		pthread_mutex_unlock(&wl->txq_event_mutex);
	}
	return 0;
}


int wilc_start_firmware(struct wilc_dev *wilc)
{
	int ret = 0;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Starting Firmware ...\n", __func__);

	ret = wilc_wlan_start(wilc);
	if (ret < 0) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Failed to start Firmware\n", __func__);
		return ret;
	}

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Waiting for FW to get ready ...\n", __func__);

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] out\n", __func__);

	uint64_t tmo = (uint64_t) 2 * 1000 * 1000 * 1000;
	pthread_sleepon_lock();

	if (pthread_sleepon_timedwait(&wilc->sync_event, tmo) != EOK) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Firmware start timed out \n", __func__);
		return -ETIME;
	}
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Firmware successfully started \n", __func__);

	pthread_sleepon_unlock();

	return 0;
}

static int wilc_firmware_download(struct wilc_dev *wilc)
{

	int ret = 0;

	if (!wilc->fw_file) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Opening file\n");
		wilc->fw_file = fopen ("/lib/firmware/wilc/wilc1000_wifi_firmware.bin", "rb");
		if (wilc->fw_file == NULL)
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Fail to open file\n");
	}

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Downloading Firmware ...\n");
	ret = wilc_wlan_firmware_download(wilc, wilc->fw_file);
	if (ret < 0)
		goto fail;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Downloading Succeeded\n");


fail:
	fclose(wilc->fw_file);
	wilc->fw_file = NULL;

	return ret;
}

int wilc_init_fw_config(struct wilc_dev *dev, struct wilc_vif *vif)
{
	struct wilc_priv *priv = &vif->priv;
	struct host_if_drv *hif_drv;
	u8 b;
	u16 hw;
	u32 w;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Start configuring Firmware\n", __func__);
	hif_drv = (struct host_if_drv *)priv->hif_drv;
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Host = %p\n", __func__, hif_drv);

	w = vif->iftype;
	//cpu_to_le32s(&w);
	if (!cfg_set(vif, 1, WID_SET_OPERATION_MODE, (u8 *)&w, 4, 0, 0))
		goto fail;

	b = WILC_FW_BSS_TYPE_INFRA;
	if (!cfg_set(vif, 0, WID_BSS_TYPE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_TX_RATE_AUTO;
	if (!cfg_set(vif, 0, WID_CURRENT_TX_RATE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_OPER_MODE_G_MIXED_11B_2;
	if (!cfg_set(vif, 0, WID_11G_OPERATING_MODE, &b, 1, 0,
			       0))
		goto fail;

	b = WILC_FW_PREAMBLE_AUTO;
	if (!cfg_set(vif, 0, WID_PREAMBLE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_11N_PROT_AUTO;
	if (!cfg_set(vif, 0, WID_11N_PROT_MECH, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_ACTIVE_SCAN;
	if (!cfg_set(vif, 0, WID_SCAN_TYPE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_SITE_SURVEY_OFF;
	if (!cfg_set(vif, 0, WID_SITE_SURVEY, &b, 1, 0, 0))
		goto fail;

	hw = 0xffff;
	//cpu_to_le16s(&hw);
	if (!cfg_set(vif, 0, WID_RTS_THRESHOLD, (u8 *)&hw, 2, 0, 0))
		goto fail;

	hw = 2346;
	//cpu_to_le16s(&hw);
	if (!cfg_set(vif, 0, WID_FRAG_THRESHOLD, (u8 *)&hw, 2, 0, 0))
		goto fail;

	b = 0;
	if (!cfg_set(vif, 0, WID_BCAST_SSID, &b, 1, 0, 0))
		goto fail;

	b = 1;
	if (!cfg_set(vif, 0, WID_QOS_ENABLE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_NO_POWERSAVE;
	if (!cfg_set(vif, 0, WID_POWER_MANAGEMENT, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_SEC_NO;
	if (!cfg_set(vif, 0, WID_11I_MODE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_AUTH_OPEN_SYSTEM;
	if (!cfg_set(vif, 0, WID_AUTH_TYPE, &b, 1, 0, 0))
		goto fail;

	b = 3;
	if (!cfg_set(vif, 0, WID_LISTEN_INTERVAL, &b, 1, 0, 0))
		goto fail;

	b = 3;
	if (!cfg_set(vif, 0, WID_DTIM_PERIOD, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_ACK_POLICY_NORMAL;
	if (!cfg_set(vif, 0, WID_ACK_POLICY, &b, 1, 0, 0))
		goto fail;

	b = 0;
	if (!cfg_set(vif, 0, WID_USER_CONTROL_ON_TX_POWER, &b, 1,
			       0, 0))
		goto fail;

	b = 48;
	if (!cfg_set(vif, 0, WID_TX_POWER_LEVEL_11A, &b, 1, 0,
			       0))
		goto fail;

	b = 28;
	if (!cfg_set(vif, 0, WID_TX_POWER_LEVEL_11B, &b, 1, 0,
			       0))
		goto fail;

	hw = 100;
	//cpu_to_le16s(&hw);
	if (!cfg_set(vif, 0, WID_BEACON_INTERVAL, (u8 *)&hw, 2, 0, 0))
		goto fail;

	b = WILC_FW_REKEY_POLICY_DISABLE;
	if (!cfg_set(vif, 0, WID_REKEY_POLICY, &b, 1, 0, 0))
		goto fail;

	w = 84600;
	//cpu_to_le32s(&w);
	if (!cfg_set(vif, 0, WID_REKEY_PERIOD, (u8 *)&w, 4, 0, 0))
		goto fail;

	w = 500;
	//cpu_to_le32s(&w);
	if (!cfg_set(vif, 0, WID_REKEY_PACKET_COUNT, (u8 *)&w, 4, 0,
			       0))
		goto fail;

	b = 1;
	if (!cfg_set(vif, 0, WID_SHORT_SLOT_ALLOWED, &b, 1, 0,
			       0))
		goto fail;

	b = WILC_FW_ERP_PROT_SELF_CTS;
	if (!cfg_set(vif, 0, WID_11N_ERP_PROT_TYPE, &b, 1, 0, 0))
		goto fail;

	b = 1;
	if (!cfg_set(vif, 0, WID_11N_ENABLE, &b, 1, 0, 0))
		goto fail;

	b = WILC_FW_11N_OP_MODE_HT_MIXED;
	if (!cfg_set(vif, 0, WID_11N_OPERATING_MODE, &b, 1, 0,
			       0))
		goto fail;

	b = 1;
	if (!cfg_set(vif, 0, WID_11N_TXOP_PROT_DISABLE, &b, 1, 0,
			       0))
		goto fail;

	b = WILC_FW_OBBS_NONHT_DETECT_PROTECT_REPORT;
	if (!cfg_set(vif, 0, WID_11N_OBSS_NONHT_DETECTION, &b, 1,
			       0, 0))
		goto fail;

	b = WILC_FW_HT_PROT_RTS_CTS_NONHT;
	if (!cfg_set(vif, 0, WID_11N_HT_PROT_TYPE, &b, 1, 0, 0))
		goto fail;

	b = 0;
	if (!cfg_set(vif, 0, WID_11N_RIFS_PROT_ENABLE, &b, 1, 0,
			       0))
		goto fail;

	b = 7;
	if (!cfg_set(vif, 0, WID_11N_CURRENT_TX_MCS, &b, 1, 0,
			       0))
		goto fail;

	b = 1;
	if (!cfg_set(vif, 0, WID_11N_IMMEDIATE_BA_ENABLED, &b, 1,
			       1, 0))
		goto fail;

	return 0;

fail:
	return -1;
}

static void wlan_deinitialize_threads(struct wilc_vif *vif)
{
	struct wilc_dev *wl = vif->wilc;

	PRINT_INFO(INIT_DBG, "Deinitializing Threads\n");
	if (!recovery_on) {
		PRINT_INFO(INIT_DBG, "Deinit debug Thread\n");
		debug_running = false;
		//if (&wl->debug_thread_started)
		{
			pthread_mutex_lock(&wl->debug_thread_started_mutex);
			pthread_cond_signal(&wl->debug_thread_started);
			pthread_mutex_unlock(&wl->debug_thread_started_mutex);
		}

	}

	wl->close = 1;
	PRINT_INFO(INIT_DBG, "Deinitializing Threads\n");

	pthread_mutex_lock(&wl->txq_event_mutex);
	pthread_cond_signal(&wl->txq_event);
	pthread_mutex_unlock(&wl->txq_event_mutex);

	if (wl->txq_thread >= 0) {
		pthread_cancel(wl->txq_thread);
		wl->txq_thread = -1;
	}
}

static void wilc_wlan_deinitialize(struct wilc_vif *vif)
{
	int ret;
	struct wilc_dev *wl = vif->wilc;

	if (wl->initialized) {
		PRINT_INFO(INIT_DBG, "Deinitializing wilc  ...\n");

		if (!wl) {
			PRINT_ER(dev, "wl is NULL\n");
			return;
		}

		PRINT_D(INIT_DBG, "destroy aging timer\n");

		PRINT_INFO(INIT_DBG, "Disabling IRQ\n");
		if (wl->io_type == WILC_HIF_SPI ||
			wl->io_type == WILC_HIF_SDIO_GPIO_IRQ) {
		} else {
			if (wl->hif_func->disable_interrupt) {
				pthread_mutex_lock(&wl->hif_cs);
				wl->hif_func->disable_interrupt(wl);
				pthread_mutex_unlock(&wl->hif_cs);
			}
		}

		PRINT_INFO(INIT_DBG, "Deinitializing Threads\n");
		wlan_deinitialize_threads(vif);
		PRINT_INFO(INIT_DBG, "Deinitializing IRQ\n");

		ret = wilc_wlan_stop(wl, vif);
		if (ret != 0)
			PRINT_ER(dev, "failed in wlan_stop\n");

		PRINT_INFO(INIT_DBG, "Deinitializing WILC Wlan\n");
		wilc_wlan_cleanup(vif);

		wl->initialized = false;

		PRINT_INFO(INIT_DBG, "wilc deinitialization Done\n");
	} else {
		PRINT_INFO(INIT_DBG, "wilc is not initialized\n");
	}
}

int wlan_initialize_threads(struct wilc_dev *wilc)
{
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Initializing Threads ... \n");
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Creating kthread for transmission \n");

	pthread_attr_t		attr;
	struct sched_param	param;

	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_RR);

	param.sched_priority = 21;
	pthread_attr_setschedparam(&attr, &param);
	pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, 8192);

	nw_pthread_create(&wilc->txq_nw, NULL,
			(void *)pkt_rx_task, wilc, 0,
			pkt_rx_task_init_fn, wilc);

	/* Create SDIO event handler */
	if (pthread_create(&wilc->txq_thread, &attr, (void *)wilc_txq_task, wilc)) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"sdio_start:  Unable to create event handler\n");
		return -1;
	}

	if ((wilc->txq_thread) < 0) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"couldn't create TXQ thread\n");
		wilc->close = 1;
		return (wilc->txq_thread);
	}

	pthread_sleepon_lock();
	if (pthread_sleepon_wait(&wilc->txq_thread_started) != EOK) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Fail to wait TXQ Thread start \n", __func__);
	}
	pthread_sleepon_unlock();

	return 0;
}


static int wilc_wlan_initialize(struct wilc_vif *vif)
{
	int ret = 0;
	struct wilc_dev *wl = vif->wilc;

	if (!wl->initialized) {
		wl->mac_status = WILC_MAC_STATUS_INIT;
		wl->close = 0;
		wl->initialized = 0;

		ret = wilc_wlan_init(vif);
		if (ret < 0) {
			PRINT_ER(dev, "Initializing WILC_Wlan FAILED\n");
			return -EIO;
		}
		PRINT_INFO(GENERIC_DBG,
			   "WILC Initialization done\n");

		ret = wlan_initialize_threads(wl);
		if (ret < 0) {
			PRINT_ER(dev, "Initializing Threads FAILED\n");
			ret = -EIO;
			goto fail_wilc_wlan;
		}

		wilc_intr_thread_create(wl);

		//if (init_irq(dev)) {
		//	ret = -EIO;
		//	goto fail_threads;
		//}

		if (wl->io_type == WILC_HIF_SDIO &&
		    wl->hif_func->enable_interrupt(wl)) {
			PRINT_ER(dev, "couldn't initialize IRQ\n");
			ret = -EIO;
			goto fail_irq_init;
		}

		ret = wilc_firmware_download(wl);
		if (ret < 0) {
			PRINT_ER(dev, "Failed to download firmware\n");
			ret = -EIO;
			goto fail_irq_enable;
		}

		ret = wilc_start_firmware(wl);
		if (ret < 0) {
			PRINT_ER(dev, "Failed to start firmware\n");
			ret = -EIO;
			goto fail_irq_enable;
		}

		if (cfg_get(vif, 1, WID_FIRMWARE_VERSION, 1, 0)) {
			int size;
			char firmware_ver[50];

			size = cfg_get_val(wl, WID_FIRMWARE_VERSION,
						     (uint8_t *)firmware_ver,
						     sizeof(firmware_ver));
			firmware_ver[size] = '\0';
			PRINT_INFO(INIT_DBG, "WILC Firmware Ver = %s\n",
				   firmware_ver);

			printf("WILC Firmware Ver = %s\n", firmware_ver);
		}

		ret = wilc_init_fw_config(wl, vif);
		if (ret < 0) {
			PRINT_ER(dev, "Failed to configure firmware\n");
			ret = -EIO;
			goto fail_fw_start;
		}

		wl->initialized = true;
		return 0;

fail_fw_start:
		wilc_wlan_stop(wl, vif);

fail_irq_enable:
		if (wl->io_type == WILC_HIF_SDIO)
			wl->hif_func->disable_interrupt(wl);
fail_irq_init:
		//deinit_irq(dev);

//fail_threads:
		///wlan_deinitialize_threads(dev);
fail_wilc_wlan:
		wilc_wlan_cleanup(vif);
		PRINT_ER(dev, "WLAN initialization FAILED\n");
	} else {
		PRINT_INFO(INIT_DBG, "wilc already initialized\n");
	}
	return ret;
}

int wilc_mac_open(struct wilc_vif *vif, unsigned char mac_add[])
{
	struct wilc_dev *wilc = vif->wilc;
	struct wilc_priv *priv = &vif->priv;
	int ret = 0;

	if (!wilc) {
		PRINT_ER(ndev, "device not ready\n");
		return -ENODEV;
	}

	PRINT_INFO(INIT_DBG, "MAC OPEN[]\n");

	PRINT_INFO(INIT_DBG, "*** re-init ***\n");
	ret = wilc_wlan_initialize(vif);
	if (ret < 0) {
		PRINT_ER(ndev, "Failed to initialize wilc\n");
		if (!recovery_on)
			wilc_deinit_host_int(vif);
		return ret;
	}

	wait_for_recovery = 0;
	wilc_set_operation_mode(vif, wilc_get_vif_idx(vif),
				 vif->iftype, vif->idx);
	wilc_get_mac_address(vif, mac_add);
	slogf(_SLOGC_NETWORK, _SLOG_INFO,"Mac address: %x %x %x %x %x %x\n", mac_add[0], mac_add[1], mac_add[2], mac_add[3], mac_add[4], mac_add[5]);

	wilc->open_ifcs++;
	priv->p2p.local_random = 0x01;
	vif->mac_opened = 1;
	return 0;
}

int wilc_mac_close(struct wilc_vif *vif)
{
	struct wilc_dev *wl = vif->wilc;

	PRINT_INFO(GENERIC_DBG, "Mac close\n");

	if (wl->open_ifcs > 0) {
		wl->open_ifcs--;
	} else {
		PRINT_ER(ndev, "MAC close called with no opened interfaces\n");
		return 0;
	}

	handle_connect_cancel(vif);

	if (!recovery_on)
		wilc_deinit_host_int(vif);

	if (wl->open_ifcs == 0) {
		PRINT_INFO(GENERIC_DBG, "Deinitializing wilc\n");
		wl->close = 1;

		wilc_wlan_deinitialize(vif);
	}

	vif->mac_opened = 0;

	return 0;
}

void wilc_wfi_mgmt_rx(struct wilc_dev *wilc, u8 *buff, u32 size)
{
	struct wilc_vif *vif;
	int srcu_idx;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: In\n", __func__);
	srcu_idx = srcu_read_lock(&wilc->srcu);
	list_for_each_entry_rcu(vif, &wilc->vif_list, list) {

		u16 tp = (u16) *buff;

		if (((tp == vif->frame_reg[0].type && vif->frame_reg[0].reg) ||
		    (tp == vif->frame_reg[1].type && vif->frame_reg[1].reg)) &&
			    vif->p2p_listen_state)
			wilc_wfi_p2p_rx(vif, buff, size);

		if (vif->monitor_flag)
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: wilc_wfi_monitor_rx\n", __func__);

	}
	srcu_read_unlock(&wilc->srcu, srcu_idx);
}


void wilc_netdev_cleanup(struct wilc_dev *wilc)
{
	struct wilc_vif *vif;
	int srcu_idx;

	if (!wilc)
		return;


	srcu_idx = srcu_read_lock(&wilc->srcu);
	list_for_each_entry_rcu(vif, &wilc->vif_list, list) {
		/* clear the mode */
		wilc_set_operation_mode(vif, 0, 0, 0);

	}
	srcu_read_unlock(&wilc->srcu, srcu_idx);

	flush_workqueue(wilc->hif_workqueue);
	destroy_workqueue(wilc->hif_workqueue);
	wilc->hif_workqueue = NULL;
	/* update the list */
	do {
		pthread_mutex_lock(&wilc->vif_mutex);
		if (wilc->vif_num <= 0) {
			pthread_mutex_unlock(&wilc->vif_mutex);
			break;
		}
		vif = wilc_get_wl_to_vif(wilc);
		if (!vif)
			list_del_rcu(&vif->list);
		wilc->vif_num--;
		pthread_mutex_unlock(&wilc->vif_mutex);
	} while (1);

	cfg_deinit(wilc);
#ifdef WILC_DEBUGFS
	wilc_debugfs_remove();
#endif

	wlan_deinit_locks(wilc);
	kfree(wilc->bus_data);
	PRINT_INFO(GENERIC_DBG, "Module_exit Done.\n");
}


static u8 wilc_get_available_idx(struct wilc_dev *wl)
{
	int idx = 0;
	struct wilc_vif *vif;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&wl->srcu);
	list_for_each_entry(vif, &wl->vif_list, list) {
		if (vif->idx == 0)
			idx = 1;
		else
			idx = 0;
	}
	srcu_read_unlock(&wl->srcu, srcu_idx);
	return idx;
}

struct wilc_vif *wilc_netdev_ifc_init(struct wilc_dev *wl, const char *name,
				      int iftype, enum nl80211_iftype type,
				      bool rtnl_locked)
{
	struct wilc_vif *vif;
	vif = (struct wilc_vif *) create_ptr(sizeof(struct wilc_vif));

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] DEBUG: vif ptr =%p\n", __func__, vif);

	vif->wilc = wl;
	vif->iftype = iftype;
	vif->idx = wilc_get_available_idx(wl);
	vif->mac_opened = 0;
	pthread_mutex_lock(&wl->vif_mutex);
	wl->vif_num += 1;
	list_add_tail(&vif->list, &wl->vif_list);
	pthread_mutex_unlock(&wl->vif_mutex);


	return vif;
}


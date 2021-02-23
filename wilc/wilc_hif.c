// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#include <sys/slogcodes.h>
#include "etherdevice.h"
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include "wilc_hif.h"
#include "workqueue.h"
#include "list.h"
#include "wilc_main.h"
#include "wilc_wfi_netdevice.h"
#include "wilc_netdev.h"
#include "ieee80211.h"
#include "cfg80211.h"
#include "type_defs.h"
#include "unaligned.h"



#define WILC_HIF_SCAN_TIMEOUT_MS                    5000
#define WILC_HIF_CONNECT_TIMEOUT_MS                 9500

#define WILC_FALSE_FRMWR_CHANNEL		    100
#define WILC_MAX_RATES_SUPPORTED		    12

/* Generic success will return 0 */
#define WILC_SUCCESS		0	/* Generic success */

/* Negative numbers to indicate failures */
/* Generic Fail */
#define	WILC_FAIL		-100
/* Busy with another operation*/
#define	WILC_BUSY		-101
/* A given argument is invalid*/
#define	WILC_INVALID_ARGUMENT	-102
/* An API request would violate the Driver state machine
 * (i.e. to start PID while not camped)
 */
#define	WILC_INVALID_STATE	-103
/* In copy operations if the copied data is larger than the allocated buffer*/
#define	WILC_BUFFER_OVERFLOW	-104
/* null pointer is passed or used */
#define WILC_NULL_PTR		-105
#define	WILC_EMPTY		-107
#define WILC_FULL		-108
#define	WILC_TIMEOUT		-109
/* The required operation have been canceled by the user*/
#define WILC_CANCELED		-110
/* The Loaded file is corruped or having an invalid format */
#define WILC_INVALID_FILE	-112
/* Cant find the file to load */
#define WILC_NOT_FOUND		-113
#define WILC_NO_MEM		-114
#define WILC_UNSUPPORTED_VERSION -115
#define WILC_FILE_EOF		-116



struct send_buffered_eap {
	void (*deliver_to_stack)(struct wilc_vif *vif, uint8_t *buff, uint32_t size,
			uint32_t pkt_offset, uint8_t status);
	void (*eap_buf_param)(void *priv);
	uint8_t *buff;
	unsigned int size;
	unsigned int pkt_offset;
	void *user_arg;
};

struct wilc_rcvd_mac_info {
	uint8_t status;
};

struct wilc_set_multicast {
	uint32_t enabled;
	uint32_t cnt;
	uint8_t *mc_list;
};

struct host_if_wowlan_trigger {
	uint8_t wowlan_trigger;
};

struct bt_coex_mode {
	uint8_t bt_coex;
};

struct host_if_set_ant {
	uint8_t mode;
	uint8_t antenna1;
	uint8_t antenna2;
	uint8_t gpio_mode;
};

struct wilc_del_all_sta {
	uint8_t assoc_sta;
	uint8_t mac[WILC_MAX_NUM_STA][ETH_ALEN];
};

struct wilc_op_mode {
	//__le32 mode;
	uint32_t mode;
};

struct wilc_reg_frame {
	bool reg;
	uint8_t reg_id;
	//__le16 frame_type;
	uint16_t frame_type;
} __packed;

struct wilc_drv_handler {
	//__le32 handler;
	uint32_t handler;
	uint8_t mode;
} __packed;

struct wilc_wep_key {
	uint8_t index;
	uint8_t key_len;
	uint8_t key[0];
} __packed;

struct wilc_sta_wpa_ptk {
	uint8_t mac_addr[ETH_ALEN];
	uint8_t key_len;
	uint8_t key[0];
} __packed;

struct wilc_ap_wpa_ptk {
	uint8_t mac_addr[ETH_ALEN];
	uint8_t index;
	uint8_t key_len;
	uint8_t key[0];
} __packed;

struct wilc_gtk_key {
	uint8_t mac_addr[ETH_ALEN];
	uint8_t rsc[8];
	uint8_t index;
	uint8_t key_len;
	uint8_t key[0];
} __packed;

union wilc_message_body {
	struct wilc_rcvd_net_info net_info;
	struct wilc_rcvd_mac_info mac_info;
	struct wilc_set_multicast mc_info;
	struct wilc_remain_ch remain_on_ch;
	char *data;
	struct send_buffered_eap send_buff_eap;
	struct host_if_set_ant set_ant;
	struct host_if_wowlan_trigger wow_trigger;
	struct bt_coex_mode bt_coex_mode;
};


struct host_if_msg {
	union wilc_message_body body;
	struct wilc_vif *vif;
	struct work_struct work;
	void (*fn)(struct work_struct *ws);
	int work_comp;
	bool is_sync;
};

struct wilc_noa_opp_enable {
	u8 ct_window;
	u8 cnt;
	__le32 duration;
	__le32 interval;
	__le32 start_time;
} __packed;

struct wilc_noa_opp_disable {
	u8 cnt;
	__le32 duration;
	__le32 interval;
	__le32 start_time;
} __packed;



struct wilc_join_bss_param {
	char ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_terminator;
	u8 bss_type;
	u8 ch;
	__le16 cap_info;
	u8 sa[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	__le16 beacon_period;
	u8 dtim_period;
	u8 supp_rates[WILC_MAX_RATES_SUPPORTED + 1];
	u8 wmm_cap;
	u8 uapsd_cap;
	u8 ht_capable;
	u8 rsn_found;
	u8 rsn_grp_policy;
	u8 mode_802_11i;
	u8 p_suites[3];
	u8 akm_suites[3];
	u8 rsn_cap[2];
	u8 noa_enabled;
	__le32 tsf_lo;
	u8 idx;
	u8 opp_enabled;
	union {
		struct wilc_noa_opp_disable opp_dis;
		struct wilc_noa_opp_enable opp_en;
	};
} __packed;

/* 'msg' should be free by the caller for syc */
static struct host_if_msg*
wilc_alloc_work(struct wilc_vif *vif, void (*work_fun)(struct work_struct *),
		bool is_sync)
{
	PRINT_D(HOSTINF_DBG, "[%s] In\n", __func__);

	if (!work_fun)
		return NULL;

	struct host_if_msg *msg = (struct host_if_msg *) create_ptr(sizeof(*msg));
	if (!msg)
		return NULL;

	msg->fn = work_fun;
	msg->work.func = work_fun;
	msg->vif = vif;
	msg->is_sync = is_sync;
	if (is_sync)
		msg->work_comp = 0;

	return msg;
}

static int wilc_enqueue_work(struct host_if_msg *msg)
{
	PRINT_D(HOSTINF_DBG, "[%s] In\n", __func__);
	INIT_WORK(&msg->work, msg->fn);

	if (!msg->vif || !msg->vif->wilc || !msg->vif->wilc->hif_workqueue)
		return -EINVAL;

	if (!queue_work(msg->vif->wilc->hif_workqueue, &msg->work))
		return -EINVAL;

	return 0;
}

/* The idx starts from 0 to (NUM_CONCURRENT_IFC - 1), but 0 index used as
 * special purpose in wilc device, so we add 1 to the index to starts from 1.
 * As a result, the returned index will be 1 to NUM_CONCURRENT_IFC.
 */
int wilc_get_vif_idx(struct wilc_vif *vif)
{
	return vif->idx + 1;
}

/* We need to minus 1 from idx which is from wilc device to get real index
 * of wilc->vif[], because we add 1 when pass to wilc device in the function
 * wilc_get_vif_idx.
 * As a result, the index should be between 0 and (NUM_CONCURRENT_IFC - 1).
 */
static struct wilc_vif *wilc_get_vif_from_idx(struct wilc_dev *wilc, int idx)
{
	int index = idx - 1;
	struct wilc_vif *vif;

	PRINT_INFO(HOSTINF_DBG, "[%s] idx=%x\n", __func__, idx);
	if (index < 0 || index >= WILC_NUM_CONCURRENT_IFC)
		return NULL;

	// Test
	vif = list_first_entry_or_null(&wilc->vif_list, typeof(*vif), list);
	PRINT_INFO(HOSTINF_DBG, "[%s] DEBUG: vif ptr =%p\n", __func__, vif);
	//

	//list_for_each_entry_rcu(vif, &wilc->vif_list, list) {
	list_for_each_entry(vif, &wilc->vif_list, list) {
		if (vif->idx == index)
			return vif;
	}

	return NULL;
}

static void handle_send_buffered_eap(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_vif *vif = msg->vif;
	struct send_buffered_eap *hif_buff_eap = &msg->body.send_buff_eap;

	PRINT_INFO(HOSTINF_DBG, "Sending bufferd eapol to WPAS\n");
	if (!hif_buff_eap->buff)
		goto out;

	if (hif_buff_eap->deliver_to_stack)
		hif_buff_eap->deliver_to_stack(vif, hif_buff_eap->buff,
					       hif_buff_eap->size,
					       hif_buff_eap->pkt_offset,
					       PKT_STATUS_BUFFERED);
	if (hif_buff_eap->eap_buf_param)
		hif_buff_eap->eap_buf_param(hif_buff_eap->user_arg);

	if (hif_buff_eap->buff != NULL) {
		kfree(hif_buff_eap->buff);
		hif_buff_eap->buff = NULL;
	}


out:
	kfree(msg);
}


int wilc_scan(struct wilc_vif *vif, u8 scan_source, u8 scan_type,
	      u8 *ch_freq_list, u8 ch_list_len,
	      void (*scan_result_fn)(enum scan_event,
	    		  struct wilc_rcvd_net_info *, void *, struct ifnet *),
	      void *user_arg, struct cfg80211_scan_request *request)
{
	int result = 0;
	struct wid wid_list[5];
	u32 index = 0;
	u32 i, scan_timeout;
	u8 *buffer;
	u8 valuesize = 0;
	u8 *search_ssid_vals = NULL;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_vif *vif_tmp;
	int srcu_idx;
	struct itimerspec setting;

	PRINT_INFO(HOSTINF_DBG, "Setting SCAN params\n");
	PRINT_INFO(HOSTINF_DBG, "Scanning: In [%d] state\n",
		   hif_drv->hif_state);

	srcu_idx = srcu_read_lock(&vif->wilc->srcu);
	list_for_each_entry_rcu(vif_tmp, &vif->wilc->vif_list, list) {
		struct host_if_drv *hif_drv_tmp;

		if (vif_tmp == NULL || vif_tmp->hif_drv == NULL)
			continue;

		hif_drv_tmp = vif_tmp->hif_drv;

		if (hif_drv_tmp->hif_state != HOST_IF_IDLE &&
		    hif_drv_tmp->hif_state != HOST_IF_CONNECTED) {
			PRINT_INFO(GENERIC_DBG,
				   "Abort scan. In state [%d]\n",
				   hif_drv_tmp->hif_state);
			result = -EBUSY;
			srcu_read_unlock(&vif->wilc->srcu, srcu_idx);
			goto error;
		}
	}
	srcu_read_unlock(&vif->wilc->srcu, srcu_idx);

	if (vif->connecting) {
		PRINT_INFO(GENERIC_DBG,
			   "Don't do scan in (CONNECTING) state\n");
		result = -EBUSY;
		goto error;
	}

	PRINT_INFO(HOSTINF_DBG, "Setting SCAN params\n");
	hif_drv->usr_scan_req.ch_cnt = 0;

	if (request->n_ssids) {
		for (i = 0; i < request->n_ssids; i++)
			valuesize += ((request->ssids[i].ssid_len) + 1);
		search_ssid_vals = create_ptr(valuesize + 1);
		if (search_ssid_vals) {
			wid_list[index].id = WID_SSID_PROBE_REQ;
			wid_list[index].type = WID_STR;
			wid_list[index].val = (s8 *)search_ssid_vals;
			buffer = (u8 *)wid_list[index].val;

			*buffer++ = request->n_ssids;

		PRINT_INFO(HOSTINF_DBG,
			   "In Handle_ProbeRequest number of ssid %d\n",
			 request->n_ssids);
			for (i = 0; i < request->n_ssids; i++) {
				*buffer++ = request->ssids[i].ssid_len;
				memcpy(buffer, request->ssids[i].ssid,
				       request->ssids[i].ssid_len);
				buffer += request->ssids[i].ssid_len;
			}
			wid_list[index].size = (s32)(valuesize + 1);
			index++;
		}
	}

	wid_list[index].id = WID_INFO_ELEMENT_PROBE;
	wid_list[index].type = WID_BIN_DATA;
	wid_list[index].val = (s8 *)request->ie;
	wid_list[index].size = request->ie_len;
	index++;

	wid_list[index].id = WID_SCAN_TYPE;
	wid_list[index].type = WID_CHAR;
	wid_list[index].size = sizeof(char);
	wid_list[index].val = (s8 *)&scan_type;
	index++;


	if (scan_type == WILC_FW_PASSIVE_SCAN && request->duration) {
		wid_list[index].id = WID_PASSIVE_SCAN_TIME;
		wid_list[index].type = WID_SHORT;
		wid_list[index].size = sizeof(u16);
		wid_list[index].val = (s8 *)&request->duration;
		index++;

		scan_timeout = (request->duration * ch_list_len) + 500;
	} else {
		scan_timeout = WILC_HIF_SCAN_TIMEOUT_MS;
	}

	wid_list[index].id = WID_SCAN_CHANNEL_LIST;
	wid_list[index].type = WID_BIN_DATA;

	if (ch_freq_list && ch_list_len > 0) {
		for (i = 0; i < ch_list_len; i++) {
			if (ch_freq_list[i] > 0)
				ch_freq_list[i] -= 1;
		}
	}

	wid_list[index].val = (s8 *)ch_freq_list;
	wid_list[index].size = ch_list_len;
	index++;

	wid_list[index].id = WID_START_SCAN_REQ;
	wid_list[index].type = WID_CHAR;
	wid_list[index].size = sizeof(char);
	wid_list[index].val = (s8 *)&scan_source;
	index++;

	hif_drv->usr_scan_req.scan_result = scan_result_fn;
	hif_drv->usr_scan_req.arg = user_arg;
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, wid_list, index);
	if (result) {
		PRINT_ER(vif->ndev, "Failed to send scan parameters\n");
		goto error;
	} else {
		hif_drv->scan_timer_vif = vif;
		PRINT_INFO(HOSTINF_DBG,
			   ">> Starting the SCAN timer\n");

		setting.it_value.tv_sec = 0;
		setting.it_value.tv_nsec = scan_timeout* 1000* 1000;
		timer_settime (hif_drv->scan_timer, 0, &setting, 0);
	}

error:

	kfree(search_ssid_vals);

	return result;
}

int32_t handle_scan_done(struct wilc_vif *vif, enum scan_event evt)
{
	int32_t result = 0;
	uint8_t abort_running_scan;
	struct wid wid;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_user_scan_req *scan_req;
	struct ifnet *ifp = vif->wilc->sc_ic.ic_ifp;
	uint8_t null_bssid[6] = {0};

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"handling scan done\n");

	if (!hif_drv) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"hif driver is NULL\n");
		return result;
	}

	if (evt == SCAN_EVENT_DONE) {
		if (memcmp(hif_drv->assoc_bssid, null_bssid, ETH_ALEN) == 0)
			hif_drv->hif_state = HOST_IF_IDLE;
		else
			hif_drv->hif_state = HOST_IF_CONNECTED;
	} else if (evt == SCAN_EVENT_ABORTED) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"bort running scan\n");
		abort_running_scan = 1;
		wid.id = WID_ABORT_RUNNING_SCAN;
		wid.type = WID_CHAR;
		wid.val = (s8 *)&abort_running_scan;
		wid.size = sizeof(char);

		result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
		if (result) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to set abort running\n");
			result = -EFAULT;
		}
	}

	scan_req = &hif_drv->usr_scan_req;
	if (scan_req->scan_result) {
		scan_req->scan_result(evt, NULL, scan_req->arg, ifp);
		scan_req->scan_result = NULL;
	}
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] Out\n", __func__);
	return result;
}

void print_bss_param(struct wilc_join_bss_param *bss_param)
{
	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->ssid = %s", __func__,bss_param->ssid);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->ssid_terminator = %d", __func__,bss_param->ssid_terminator);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->bss_type = %d", __func__,bss_param->bss_type);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->ch = 0x%x", __func__,bss_param->ch);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->cap_info = 0x%x", __func__, bss_param->cap_info);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->sa = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x", __func__, bss_param->sa[0], bss_param->sa[1], bss_param->sa[2], bss_param->sa[3], bss_param->sa[4], bss_param->sa[5]);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->bssid = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x", __func__, bss_param->bssid[0], bss_param->bssid[1], bss_param->bssid[2], bss_param->bssid[3], bss_param->bssid[4], bss_param->bssid[5]);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->beacon_period = 0x%x", __func__,bss_param->beacon_period);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->>dtim_period = 0x%x", __func__,bss_param->dtim_period);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->supp_rates = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x", __func__, bss_param->supp_rates[0], bss_param->supp_rates[1], bss_param->supp_rates[2], bss_param->supp_rates[3], bss_param->supp_rates[4],  bss_param->supp_rates[5], bss_param->supp_rates[6], bss_param->supp_rates[7], bss_param->supp_rates[8], bss_param->supp_rates[9], bss_param->supp_rates[10], bss_param->supp_rates[11], bss_param->supp_rates[12]);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->wmm_cap = 0x%x", __func__,bss_param->wmm_cap);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->uapsd_cap = 0x%x", __func__,bss_param->uapsd_cap);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->ht_capable = 0x%x", __func__,bss_param->ht_capable);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->rsn_found = 0x%x", __func__,bss_param->rsn_found);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->rsn_grp_policy = 0x%x", __func__,bss_param->rsn_grp_policy);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->mode_802_11i = 0x%x", __func__,bss_param->mode_802_11i);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->p_suites = 0x%x 0x%x 0x%x", __func__,bss_param->p_suites[0], bss_param->p_suites[1], bss_param->p_suites[2]);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->akm_suites = 0x%x 0x%x 0x%x", __func__,bss_param->akm_suites[0], bss_param->akm_suites[1], bss_param->akm_suites[2]);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->akm_suites = 0x%x 0x%x", __func__,bss_param->rsn_cap[0], bss_param->rsn_cap[1]);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->noa_enabled = 0x%x", __func__,bss_param->noa_enabled);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->tsf_lo = 0x%x", __func__,bss_param->tsf_lo);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->idx = 0x%x", __func__,bss_param->idx);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->opp_enabled = 0x%x", __func__,bss_param->opp_enabled);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->opp_dis.cnt = 0x%x", __func__,bss_param->opp_dis.cnt);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->opp_dis.duration = 0x%x", __func__,bss_param->opp_dis.duration);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->opp_dis.interval = 0x%x", __func__,bss_param->opp_dis.interval);

	slogf(_SLOGC_NETWORK, _SLOG_INFO,"[%s] bss_param->opp_dis.start_time = 0x%x", __func__,bss_param->opp_dis.start_time);


}

static int wilc_send_connect_wid(struct wilc_vif *vif)
{
	int result = 0;
	struct wid wid_list[4];
	u32 wid_cnt = 0;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_conn_info *conn_attr = &hif_drv->conn_info;
	struct wilc_join_bss_param *bss_param = hif_drv->conn_info.param;
	struct wilc_vif *vif_tmp;

	PRINT_D(HOSTINF_DBG, "[%s] In\n", __func__);

	//print_bss_param(bss_param);

	list_for_each_entry(vif_tmp, &vif->wilc->vif_list, list) {

		struct host_if_drv *hif_drv_tmp;

		if (vif_tmp == NULL || vif_tmp->hif_drv == NULL)
			continue;

		hif_drv_tmp = vif_tmp->hif_drv;

		if (hif_drv_tmp->hif_state == HOST_IF_SCANNING) {
			PRINT_INFO(GENERIC_DBG,
				   "Abort connect in state [%d]\n",
				   hif_drv_tmp->hif_state);
			result = -EBUSY;
			goto error;
		}
	}


	wid_list[wid_cnt].id = WID_INFO_ELEMENT_ASSOCIATE;
	wid_list[wid_cnt].type = WID_BIN_DATA;
	wid_list[wid_cnt].val = (s8 *)conn_attr->req_ies;
	wid_list[wid_cnt].size = conn_attr->req_ies_len;
	wid_cnt++;

	wid_list[wid_cnt].id = WID_11I_MODE;
	wid_list[wid_cnt].type = WID_CHAR;
	wid_list[wid_cnt].size = sizeof(char);
	wid_list[wid_cnt].val = (s8 *)&conn_attr->security;
	wid_cnt++;

	PRINT_D(HOSTINF_DBG, "Encrypt Mode = %x\n",
		conn_attr->security);
	wid_list[wid_cnt].id = WID_AUTH_TYPE;
	wid_list[wid_cnt].type = WID_CHAR;
	wid_list[wid_cnt].size = sizeof(char);
	wid_list[wid_cnt].val = (s8 *)&conn_attr->auth_type;
	wid_cnt++;

	PRINT_D(HOSTINF_DBG, "Authentication Type = %x\n",
		conn_attr->auth_type);
	PRINT_INFO(HOSTINF_DBG,
		   "Connecting to network on channel %d\n", conn_attr->ch);

	wid_list[wid_cnt].id = WID_JOIN_REQ_EXTENDED;
	wid_list[wid_cnt].type = WID_STR;
	wid_list[wid_cnt].size = sizeof(*bss_param);
	wid_list[wid_cnt].val = (s8 *)bss_param;
	wid_cnt++;

	PRINT_INFO(GENERIC_DBG, "send HOST_IF_WAITING_CONN_RESP\n");

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, wid_list, wid_cnt);
	if (result) {
		PRINT_ER(vif->ndev, "failed to send config packet\n");
		goto error;
	} else {
		PRINT_INFO(GENERIC_DBG,
			   "set HOST_IF_WAITING_CONN_RESP\n");
		hif_drv->hif_state = HOST_IF_WAITING_CONN_RESP;
	}

	return 0;

error:

	kfree(conn_attr->req_ies);
	conn_attr->req_ies = NULL;

	return result;
}

void handle_connect_cancel(struct wilc_vif *vif)
{
	struct host_if_drv *hif_drv = vif->hif_drv;

	if (hif_drv->conn_info.conn_result) {
		hif_drv->conn_info.conn_result(EVENT_DISCONN_NOTIF,
					       0, vif);
	}

	eth_zero_addr(hif_drv->assoc_bssid);

	hif_drv->conn_info.req_ies_len = 0;
	kfree(hif_drv->conn_info.req_ies);
	hif_drv->conn_info.req_ies = NULL;
	hif_drv->hif_state = HOST_IF_IDLE;
}


static void handle_connect_timeout(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_vif *vif = msg->vif;
	int result;
	struct wid wid;
	uint16_t dummy_reason_code = 0;
	struct host_if_drv *hif_drv = vif->hif_drv;

	if (!hif_drv) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"hif driver is NULL\n");
		goto out;
	}

	hif_drv->hif_state = HOST_IF_IDLE;

	if (hif_drv->conn_info.conn_result) {
		hif_drv->conn_info.conn_result(EVENT_CONN_RESP,
							       WILC_MAC_STATUS_DISCONNECTED,
							       vif);

	} else {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"conn_result is NULL\n");
	}

	wid.id = WID_DISCONNECT;
	wid.type = WID_CHAR;
	wid.val = (s8 *)&dummy_reason_code;
	wid.size = sizeof(char);

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Sending disconnect request\n");
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to send disconect\n");

	hif_drv->conn_info.req_ies_len = 0;
	free_ptr(hif_drv->conn_info.req_ies);
	hif_drv->conn_info.req_ies = NULL;

out:
	free_ptr(msg);
}

const u8 *cfg80211_find_ie(u8 eid, const u8 *ies, int len)
{
	while (len > 2 && ies[0] != eid) {
		 len -= ies[1] + 2;
		 ies += ies[1] + 2;
	}
	if (len < 2)
		return NULL;
	if (len < 2 + ies[1])
		return NULL;
	return ies;
}

const u8 *cfg80211_find_vendor_ie(unsigned int oui, u8 oui_type,
				  const u8 *ies, int len)
{
	struct ieee80211_vendor_ie *ie;
	const u8 *pos = ies, *end = ies + len;
	int ie_oui;

	while (pos < end) {
		pos = cfg80211_find_ie(WLAN_EID_VENDOR_SPECIFIC, pos,
				       end - pos);
		if (!pos)
			return NULL;

		ie = (struct ieee80211_vendor_ie *)pos;


		if (ie->len < sizeof(*ie))
			goto cont;

		ie_oui = ie->oui[0] << 16 | ie->oui[1] << 8 | ie->oui[2];
		if (ie_oui == oui && ie->oui_type == oui_type)
			return pos;
cont:
		pos += 2 + ie->len;
	}
	return NULL;
}

int cfg80211_get_p2p_attr(const u8 *ies, unsigned int len,
			  enum ieee80211_p2p_attr_id attr,
			  u8 *buf, unsigned int bufsize)
{
	u8 *out = buf;
	u16 attr_remaining = 0;
	bool desired_attr = false;
	u16 desired_len = 0;

	while (len > 0) {
		unsigned int iedatalen;
		unsigned int copy;
		const u8 *iedata;

		if (len < 2)
			return -EILSEQ;
		iedatalen = ies[1];
		if (iedatalen + 2 > len)
			return -EILSEQ;

		if (ies[0] != WLAN_EID_VENDOR_SPECIFIC)
			goto cont;

		if (iedatalen < 4)
			goto cont;

		iedata = ies + 2;

		/* check WFA OUI, P2P subtype */
		if (iedata[0] != 0x50 || iedata[1] != 0x6f ||
		    iedata[2] != 0x9a || iedata[3] != 0x09)
			goto cont;

		iedatalen -= 4;
		iedata += 4;

		/* check attribute continuation into this IE */
		copy = min_t(unsigned int, attr_remaining, iedatalen);
		if (copy && desired_attr) {
			desired_len += copy;
			if (out) {
				memcpy(out, iedata, min(bufsize, copy));
				out += min(bufsize, copy);
				bufsize -= min(bufsize, copy);
			}


			if (copy == attr_remaining)
				return desired_len;
		}

		attr_remaining -= copy;
		if (attr_remaining)
			goto cont;

		iedatalen -= copy;
		iedata += copy;

		while (iedatalen > 0) {
			u16 attr_len;

			/* P2P attribute ID & size must fit */
			if (iedatalen < 3)
				return -EILSEQ;
			desired_attr = iedata[0] == attr;
			//attr_len = get_unaligned_le16(iedata + 1);
			memcpy(&attr_len, iedata, 2);
			attr_len +=1;
			iedatalen -= 3;
			iedata += 3;

			copy = min_t(unsigned int, attr_len, iedatalen);

			if (desired_attr) {
				desired_len += copy;
				if (out) {
					memcpy(out, iedata, min(bufsize, copy));
					out += min(bufsize, copy);
					bufsize -= min(bufsize, copy);
				}

				if (copy == attr_len)
					return desired_len;
			}

			iedata += copy;
			iedatalen -= copy;
			attr_remaining = attr_len - copy;
		}

 cont:
		len -= ies[1] + 2;
		ies += ies[1] + 2;
	}

	if (attr_remaining && desired_attr)
		return -EILSEQ;

	return -ENOENT;
}


void *wilc_parse_join_bss_param(struct cfg80211_bss *bss,
				struct cfg80211_crypto_settings *crypto)
{
	struct wilc_join_bss_param *param;
	struct ieee80211_p2p_noa_attr noa_attr;
	u8 rates_len = 0;
	const u8 *tim_elm, *ssid_elm, *rates_ie, *supp_rates_ie;
	const u8 *ht_ie, *wpa_ie, *wmm_ie, *rsn_ie;
	int ret;
	const struct cfg80211_bss_ies *ies = bss->ies;

	param = (struct wilc_join_bss_param *) create_ptr(sizeof(*param));
	if (!param)
		return NULL;

	memset(param, 0, sizeof(*param));

	param->beacon_period = cpu_to_le16(bss->beacon_interval);
	param->cap_info = cpu_to_le16(bss->capability);
	param->bss_type = WILC_FW_BSS_TYPE_INFRA;
	param->ch = bss->channel;
	ether_addr_copy(param->bssid, bss->bssid);

	ssid_elm = cfg80211_find_ie(WLAN_EID_SSID, ies->data, ies->len);
	if (ssid_elm) {
		if (ssid_elm[1] <= IEEE80211_MAX_SSID_LEN)
			memcpy(param->ssid, ssid_elm + 2, ssid_elm[1]);
	}

	tim_elm = cfg80211_find_ie(WLAN_EID_TIM, ies->data, ies->len);
	if (tim_elm && tim_elm[1] >= 2)
		param->dtim_period = tim_elm[3];

	memset(param->p_suites, 0xFF, 3);
	memset(param->akm_suites, 0xFF, 3);

	rates_ie = cfg80211_find_ie(WLAN_EID_SUPP_RATES, ies->data, ies->len);
	if (rates_ie) {
		rates_len = rates_ie[1];
		if (rates_len > WILC_MAX_RATES_SUPPORTED)
			rates_len = WILC_MAX_RATES_SUPPORTED;
		param->supp_rates[0] = rates_len;
		memcpy(&param->supp_rates[1], rates_ie + 2, rates_len);
	}

	supp_rates_ie = cfg80211_find_ie(WLAN_EID_EXT_SUPP_RATES, ies->data,
					 ies->len);
	if (supp_rates_ie) {
		if (supp_rates_ie[1] > (WILC_MAX_RATES_SUPPORTED - rates_len))
			param->supp_rates[0] = WILC_MAX_RATES_SUPPORTED;
		else
			param->supp_rates[0] += supp_rates_ie[1];

		memcpy(&param->supp_rates[rates_len + 1], supp_rates_ie + 2,
		       (param->supp_rates[0] - rates_len));
	}

	ht_ie = cfg80211_find_ie(WLAN_EID_HT_CAPABILITY, ies->data, ies->len);
	if (ht_ie)
		param->ht_capable = true;

	ret = cfg80211_get_p2p_attr(ies->data, ies->len,
				    IEEE80211_P2P_ATTR_ABSENCE_NOTICE,
				    (u8 *)&noa_attr, sizeof(noa_attr));
	if (ret > 0) {
		param->tsf_lo = cpu_to_le32(ies->tsf);
		param->noa_enabled = 1;
		param->idx = noa_attr.index;
		if (noa_attr.oppps_ctwindow & IEEE80211_P2P_OPPPS_ENABLE_BIT) {
			param->opp_enabled = 1;
			param->opp_en.ct_window = noa_attr.oppps_ctwindow;
			param->opp_en.cnt = noa_attr.desc[0].count;
			param->opp_en.duration = noa_attr.desc[0].duration;
			param->opp_en.interval = noa_attr.desc[0].interval;
			param->opp_en.start_time = noa_attr.desc[0].start_time;
		} else {
			param->opp_enabled = 0;
			param->opp_dis.cnt = noa_attr.desc[0].count;
			param->opp_dis.duration = noa_attr.desc[0].duration;
			param->opp_dis.interval = noa_attr.desc[0].interval;
			param->opp_dis.start_time = noa_attr.desc[0].start_time;
		}
	}
	wmm_ie = cfg80211_find_vendor_ie(WLAN_OUI_MICROSOFT,
					 WLAN_OUI_TYPE_MICROSOFT_WMM,
					 ies->data, ies->len);
	if (wmm_ie) {
		struct ieee80211_wmm_param_ie *ie;

		ie = (struct ieee80211_wmm_param_ie *)wmm_ie;
		if ((ie->oui_subtype == 0 || ie->oui_subtype == 1) &&
		    ie->version == 1) {
			param->wmm_cap = true;
			if (ie->qos_info & BIT(7))
				param->uapsd_cap = true;
		}
	}

	wpa_ie = cfg80211_find_vendor_ie(WLAN_OUI_MICROSOFT,
					 WLAN_OUI_TYPE_MICROSOFT_WPA,
					 ies->data, ies->len);
	if (wpa_ie) {
		param->mode_802_11i = 1;
		param->rsn_found = true;
	}

	rsn_ie = cfg80211_find_ie(WLAN_EID_RSN, ies->data, ies->len);
	if (rsn_ie) {
		int offset = 8;

		param->mode_802_11i = 2;
		param->rsn_found = true;
		//extract RSN capabilities
		offset += (rsn_ie[offset] * 4) + 2;
		offset += (rsn_ie[offset] * 4) + 2;
		memcpy(param->rsn_cap, &rsn_ie[offset], 2);
	}

	if (param->rsn_found) {
		int i;

		param->rsn_grp_policy = crypto->cipher_group & 0xFF;
		for (i = 0; i < crypto->n_ciphers_pairwise && i < 3; i++)
			param->p_suites[i] = crypto->ciphers_pairwise[i] & 0xFF;

		for (i = 0; i < crypto->n_akm_suites && i < 3; i++)
			param->akm_suites[i] = crypto->akm_suites[i] & 0xFF;
	}

	return (void *)param;
}

static void handle_rcvd_ntwrk_info(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_rcvd_net_info *rcvd_info = &msg->body.net_info;
	struct wilc_user_scan_req *scan_req = &msg->vif->hif_drv->usr_scan_req;
	struct ifnet *ifp = msg->vif->wilc->sc_ic.ic_ifp;

	const u8 *ch_elm, *ssid_elm;
	u8 *ies;
	int ies_len;
	size_t offset;

	PRINT_D(HOSTINF_DBG,
		"Handling received network info\n");

	if (ieee80211_is_probe_resp(rcvd_info->mgmt->frame_control))
		offset = offsetof(struct ieee80211_mgmt, u.probe_resp.variable);
	else if (ieee80211_is_beacon(rcvd_info->mgmt->frame_control))
		offset = offsetof(struct ieee80211_mgmt, u.beacon.variable);
	else
		goto done;

	ies = rcvd_info->mgmt->u.beacon.variable;
	ies_len = rcvd_info->frame_len - offset;
	if (ies_len <= 0)
		goto done;

	PRINT_INFO(HOSTINF_DBG, "ifp= %p\n", ifp);
	PRINT_INFO(HOSTINF_DBG, "New network found\n");
	/* extract the channel from recevied mgmt frame */
	ch_elm = cfg80211_find_ie(WLAN_EID_DS_PARAMS, ies, ies_len);
	if (ch_elm && ch_elm[1] > 0)
		rcvd_info->ch = ch_elm[2];

	PRINT_INFO(HOSTINF_DBG, "New network found, ch = %d\n", rcvd_info->ch);

	ssid_elm = cfg80211_find_ie(WLAN_EID_SSID, ies, ies_len);
	PRINT_INFO(HOSTINF_DBG, "ssid = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", ssid_elm[0], ssid_elm[1], ssid_elm[2], ssid_elm[3], ssid_elm[4], ssid_elm[5], ssid_elm[6], ssid_elm[7]);

	if (scan_req->scan_result)
		scan_req->scan_result(SCAN_EVENT_NETWORK_FOUND,
				      rcvd_info, scan_req->arg, ifp);


done:
	PRINT_INFO(HOSTINF_DBG, "[%s] Out\n", __func__);
	kfree(rcvd_info->mgmt);
	kfree(msg);
}
static void host_int_get_assoc_res_info(struct wilc_vif *vif,
					uint8_t *assoc_resp_info,
					uint32_t max_assoc_resp_info_len,
					uint32_t *rcvd_assoc_resp_info_len)
{
	int result;
	struct wid wid;

	wid.id = WID_ASSOC_RES_INFO;
	wid.type = WID_STR;
	wid.val = (s8 *)assoc_resp_info;
	wid.size = max_assoc_resp_info_len;

	result = wilc_send_config_pkt(vif, WILC_GET_CFG, &wid, 1);
	if (result) {
		*rcvd_assoc_resp_info_len = 0;
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to send association response\n");
		return;
	}

	*rcvd_assoc_resp_info_len = wid.size;
}


#define WLAN_STATUS_SUCCESS 0
static int32_t wilc_parse_assoc_resp_info(uint8_t *buffer, uint32_t buffer_len,
				      struct wilc_conn_info *ret_conn_info)
{
	uint8_t *ies;
	uint16_t ies_len;
	struct assoc_resp *res = (struct assoc_resp *)buffer;

	ret_conn_info->status = res->status_code;
	if (ret_conn_info->status == WLAN_STATUS_SUCCESS) {
		ies = &buffer[sizeof(*res)];
		ies_len = buffer_len - sizeof(*res);

		ret_conn_info->resp_ies = (struct host_if_msg *) create_ptr(ies_len);
		memcpy(ret_conn_info->resp_ies, ies, ies_len);
				//kmemdup(ies, ies_len, GFP_KERNEL);
		if (!ret_conn_info->resp_ies)
			return -ENOMEM;

		ret_conn_info->resp_ies_len = ies_len;
	}

	return 0;
}
static inline void host_int_parse_assoc_resp_info(struct wilc_vif *vif,
						  uint8_t mac_status)
{
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_conn_info *conn_info = &hif_drv->conn_info;

	if (mac_status == WILC_MAC_STATUS_CONNECTED) {
		uint32_t assoc_resp_info_len;

		memset(hif_drv->assoc_resp, 0, WILC_MAX_ASSOC_RESP_FRAME_SIZE);

		host_int_get_assoc_res_info(vif, hif_drv->assoc_resp,
					    WILC_MAX_ASSOC_RESP_FRAME_SIZE,
					    &assoc_resp_info_len);

		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Received association response = %d\n", assoc_resp_info_len);

		if (assoc_resp_info_len != 0) {
			int32_t err = 0;

			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Parsing association response\n");

			err = wilc_parse_assoc_resp_info(hif_drv->assoc_resp,
							 assoc_resp_info_len,
							 conn_info);
			if (err)
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"wilc_parse_assoc_resp_info() returned error %d\n", err);

		}
	}

	timer_delete(hif_drv->connect_timer);

	conn_info->conn_result(EVENT_CONN_RESP, mac_status, vif);

	if (mac_status == WILC_MAC_STATUS_CONNECTED &&
	    conn_info->status == WLAN_STATUS_SUCCESS) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"MAC status : CONNECTED and Connect Status : Successful\n");

		hif_drv->hif_state = HOST_IF_CONNECTED;
		ether_addr_copy(hif_drv->assoc_bssid, conn_info->bssid);
	} else {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"MAC status : %d and Connect Status : %d\n", mac_status, conn_info->status);
		hif_drv->hif_state = HOST_IF_IDLE;
	}

	free_ptr(conn_info->resp_ies);
	conn_info->resp_ies = NULL;
	conn_info->resp_ies_len = 0;
	free_ptr(conn_info->req_ies);
	conn_info->req_ies = NULL;
	conn_info->req_ies_len = 0;
}

static inline void host_int_handle_disconnect(struct wilc_vif *vif)
{
	struct host_if_drv *hif_drv = vif->hif_drv;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Received WILC_MAC_STATUS_DISCONNECTED from the FW\n");

	if (hif_drv->usr_scan_req.scan_result) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"\n\n<< Abort the running OBSS Scan >>\n\n");

		timer_delete(hif_drv->scan_timer);
		handle_scan_done(vif, SCAN_EVENT_ABORTED);
	}

	if (hif_drv->conn_info.conn_result) {
		hif_drv->conn_info.conn_result(EVENT_DISCONN_NOTIF,
							       0, vif);
	} else {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Connect result NULL\n");
	}

	eth_zero_addr(hif_drv->assoc_bssid);

	hif_drv->conn_info.req_ies_len = 0;
	free_ptr(hif_drv->conn_info.req_ies);
	hif_drv->conn_info.req_ies = NULL;
	hif_drv->hif_state = HOST_IF_IDLE;
}


static void handle_rcvd_gnrl_async_info(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_vif *vif = msg->vif;
	struct wilc_rcvd_mac_info *mac_info = &msg->body.mac_info;
	struct host_if_drv *hif_drv = vif->hif_drv;

	if (!hif_drv) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: hif driver is NULL\n", __func__);
		goto free_msg;
	}

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Current State = %d,Received state = %d\n", hif_drv->hif_state, mac_info->status);


	if (!hif_drv->conn_info.conn_result) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"conn_result is NULL\n");
		goto free_msg;
	}

	host_int_parse_assoc_resp_info(vif, mac_info->status);

	if (hif_drv->hif_state == HOST_IF_WAITING_CONN_RESP) {
		host_int_parse_assoc_resp_info(vif, mac_info->status);
	} else if (mac_info->status == WILC_MAC_STATUS_DISCONNECTED) {
		if (hif_drv->hif_state == HOST_IF_CONNECTED) {
			host_int_handle_disconnect(vif);
		} else if (hif_drv->usr_scan_req.scan_result) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Received WILC_MAC_STATUS_DISCONNECTED. Abort the running Scan\n");
			timer_delete(hif_drv->scan_timer);
			handle_scan_done(vif, SCAN_EVENT_ABORTED);
		}
	}

free_msg:
	free_ptr(msg);
}


int wilc_disconnect(struct wilc_vif *vif)
{
	struct wid wid;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_user_scan_req *scan_req;
	struct wilc_conn_info *conn_info;
	struct ifnet *ifp = vif->wilc->sc_ic.ic_ifp;
	int result;
	u16 dummy_reason_code = 0;
	struct wilc_vif *vif_tmp;
	int srcu_idx;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] In\n", __func__);

	srcu_idx = srcu_read_lock(&vif->wilc->srcu);
	list_for_each_entry_rcu(vif_tmp, &vif->wilc->vif_list, list) {
		struct host_if_drv *hif_drv_tmp;

		if (vif_tmp == NULL || vif_tmp->hif_drv == NULL)
			continue;

		hif_drv_tmp = vif_tmp->hif_drv;

		if (hif_drv_tmp->hif_state == HOST_IF_SCANNING) {
			PRINT_INFO(GENERIC_DBG,
				   "Abort scan from disconnect. state [%d]\n",
				   hif_drv_tmp->hif_state);
			timer_delete(hif_drv_tmp->scan_timer);
			handle_scan_done(vif_tmp, SCAN_EVENT_ABORTED);
		}
	}
	srcu_read_unlock(&vif->wilc->srcu, srcu_idx);

	wid.id = WID_DISCONNECT;
	wid.type = WID_CHAR;
	wid.val = (s8 *)&dummy_reason_code;
	wid.size = sizeof(char);

	PRINT_INFO(HOSTINF_DBG, "Sending disconnect request\n");

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result) {
		PRINT_ER(vif->ndev, "Failed to send disconnect\n");
		return -ENOMEM;
	}

	scan_req = &hif_drv->usr_scan_req;
	conn_info = &hif_drv->conn_info;
	if (scan_req->scan_result) {
		timer_delete(hif_drv->scan_timer);
		scan_req->scan_result(SCAN_EVENT_ABORTED, NULL, scan_req->arg, ifp);
		scan_req->scan_result = NULL;
	}
	if (conn_info->conn_result) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log31\n", __func__);
		if (hif_drv->hif_state == HOST_IF_WAITING_CONN_RESP) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log34\n", __func__);
			PRINT_INFO(HOSTINF_DBG,
				   "supplicant requested disconnection\n");
			timer_delete(hif_drv->connect_timer);
			conn_info->conn_result(EVENT_CONN_RESP,
					       WILC_MAC_STATUS_DISCONNECTED,
					       vif);

		} else if (hif_drv->hif_state == HOST_IF_CONNECTED) {
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log35, %p\n", __func__, conn_info->conn_result);
			conn_info->conn_result(EVENT_DISCONN_NOTIF,
					       WILC_MAC_STATUS_DISCONNECTED,
						   vif);
		}
	} else {
		PRINT_ER(vif->ndev, "conn_result = NULL\n");
	}

	hif_drv->hif_state = HOST_IF_IDLE;

	eth_zero_addr(hif_drv->assoc_bssid);


	conn_info->req_ies_len = 0;
	kfree(conn_info->req_ies);
	conn_info->req_ies = NULL;
	conn_info->conn_result = NULL;

	return 0;
}

int wilc_get_statistics(struct wilc_vif *vif, struct rf_info *stats)
{
	struct wid wid_list[5];
	u32 wid_cnt = 0, result;

	wid_list[wid_cnt].id = WID_LINKSPEED;
	wid_list[wid_cnt].type = WID_CHAR;
	wid_list[wid_cnt].size = sizeof(char);
	wid_list[wid_cnt].val = (s8 *)&stats->link_speed;
	wid_cnt++;

	wid_list[wid_cnt].id = WID_RSSI;
	wid_list[wid_cnt].type = WID_CHAR;
	wid_list[wid_cnt].size = sizeof(char);
	wid_list[wid_cnt].val = (s8 *)&stats->rssi;
	wid_cnt++;

	wid_list[wid_cnt].id = WID_SUCCESS_FRAME_COUNT;
	wid_list[wid_cnt].type = WID_INT;
	wid_list[wid_cnt].size = sizeof(u32);
	wid_list[wid_cnt].val = (s8 *)&stats->tx_cnt;
	wid_cnt++;

	wid_list[wid_cnt].id = WID_RECEIVED_FRAGMENT_COUNT;
	wid_list[wid_cnt].type = WID_INT;
	wid_list[wid_cnt].size = sizeof(u32);
	wid_list[wid_cnt].val = (s8 *)&stats->rx_cnt;
	wid_cnt++;

	wid_list[wid_cnt].id = WID_FAILED_COUNT;
	wid_list[wid_cnt].type = WID_INT;
	wid_list[wid_cnt].size = sizeof(u32);
	wid_list[wid_cnt].val = (s8 *)&stats->tx_fail_cnt;
	wid_cnt++;

	result = wilc_send_config_pkt(vif, WILC_GET_CFG, wid_list, wid_cnt);
	if (result) {
		PRINT_ER(vif->ndev, "Failed to send scan parameters\n");
		return result;
	}

	if (stats->link_speed > TCP_ACK_FILTER_LINK_SPEED_THRESH &&
	    stats->link_speed != DEFAULT_LINK_SPEED) {
		PRINT_INFO(HOSTINF_DBG, "Enable TCP filter\n");
		wilc_enable_tcp_ack_filter(vif, true);
	} else if (stats->link_speed != DEFAULT_LINK_SPEED) {
		PRINT_INFO(HOSTINF_DBG, "Disable TCP filter %d\n",
			   stats->link_speed);
		wilc_enable_tcp_ack_filter(vif, false);
	}

	return result;
}

static void handle_get_statistics(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_vif *vif = msg->vif;
	struct rf_info *stats = (struct rf_info *)msg->body.data;

	wilc_get_statistics(vif, stats);
	kfree(msg);
}

static void wilc_hif_pack_sta_param(struct wilc_vif *vif, u8 *cur_byte,
				    const u8 *mac,
				    struct station_parameters *params)
{
	PRINT_INFO(HOSTINF_DBG, "Packing STA params\n");
	ether_addr_copy(cur_byte, mac);
	cur_byte +=  ETH_ALEN;

	put_unaligned_le16(params->aid, cur_byte);
	cur_byte += 2;

	*cur_byte++ = params->supported_rates_len;
	if (params->supported_rates_len > 0)
		memcpy(cur_byte, params->supported_rates,
		       params->supported_rates_len);
	cur_byte += params->supported_rates_len;

	if (params->ht_capa) {
		*cur_byte++ = true;
		memcpy(cur_byte, &params->ht_capa,
		       sizeof(struct ieee80211_ht_cap));
	} else {
		*cur_byte++ = false;
	}
	cur_byte += sizeof(struct ieee80211_ht_cap);

	put_unaligned_le16(params->sta_flags_mask, cur_byte);
	cur_byte += 2;
	put_unaligned_le16(params->sta_flags_set, cur_byte);
}

static int handle_remain_on_chan(struct wilc_vif *vif,
				 struct wilc_remain_ch *hif_remain_ch)
{
	int result;
	u8 remain_on_chan_flag;
	struct wid wid;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_vif *vif_tmp;
	int srcu_idx;

	if (!hif_drv) {
		PRINT_ER(vif->ndev, "Driver is null\n");
		return -EFAULT;
	}

	srcu_idx = srcu_read_lock(&vif->wilc->srcu);
	list_for_each_entry_rcu(vif_tmp, &vif->wilc->vif_list, list) {
		struct host_if_drv *hif_drv_tmp;

		if (vif_tmp == NULL || vif_tmp->hif_drv == NULL)
			continue;

		hif_drv_tmp = vif_tmp->hif_drv;

		if (hif_drv_tmp->hif_state == HOST_IF_SCANNING) {
			PRINT_INFO(GENERIC_DBG,
				   "IFC busy scanning. WLAN_IFC state %d\n",
				   hif_drv_tmp->hif_state);
			srcu_read_unlock(&vif->wilc->srcu, srcu_idx);
			return -EBUSY;
		} else if (hif_drv_tmp->hif_state != HOST_IF_IDLE &&
			   hif_drv_tmp->hif_state != HOST_IF_CONNECTED) {
			PRINT_INFO(GENERIC_DBG,
				   "IFC busy connecting. WLAN_IFC %d\n",
				   hif_drv_tmp->hif_state);
			srcu_read_unlock(&vif->wilc->srcu, srcu_idx);
			return -EBUSY;
		}
	}
	srcu_read_unlock(&vif->wilc->srcu, srcu_idx);

	if (vif->connecting) {
		PRINT_INFO(GENERIC_DBG,
			   "Don't do scan in (CONNECTING) state\n");
		return -EBUSY;
	}

	PRINT_INFO(HOSTINF_DBG,
		   "Setting channel [%d] duration[%d] [%llu]\n",
		   hif_remain_ch->ch, hif_remain_ch->duration,
		   hif_remain_ch->cookie);
	remain_on_chan_flag = true;
	wid.id = WID_REMAIN_ON_CHAN;
	wid.type = WID_STR;
	wid.size = 2;
	wid.val = create_ptr(wid.size);
	if (!wid.val)
		return -ENOMEM;

	wid.val[0] = remain_on_chan_flag;
	wid.val[1] = (s8)hif_remain_ch->ch;

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	kfree(wid.val);
	if (result) {
		PRINT_ER(vif->ndev, "Failed to set remain on channel\n");
		return -EBUSY;
	}

	hif_drv->remain_on_ch.arg = hif_remain_ch->arg;
	hif_drv->remain_on_ch.expired = hif_remain_ch->expired;
	hif_drv->remain_on_ch.ch = hif_remain_ch->ch;
	hif_drv->remain_on_ch.cookie = hif_remain_ch->cookie;
	hif_drv->hif_state = HOST_IF_P2P_LISTEN;

	hif_drv->remain_on_ch_timer_vif = vif;

	return result;
}


static int handle_roc_expired(struct wilc_vif *vif, u64 cookie)
{
	u8 remain_on_chan_flag;
	struct wid wid;
	int result;
	struct host_if_drv *hif_drv = vif->hif_drv;
	u8 null_bssid[6] = {0};

	if (hif_drv->hif_state == HOST_IF_P2P_LISTEN) {
		remain_on_chan_flag = false;
		wid.id = WID_REMAIN_ON_CHAN;
		wid.type = WID_STR;
		wid.size = 2;
		wid.val = (s8*) create_ptr(wid.size);
		if (!wid.val) {
			PRINT_ER(vif->ndev, "Failed to allocate memory\n");
			return -ENOMEM;
		}

		wid.val[0] = remain_on_chan_flag;
		wid.val[1] = WILC_FALSE_FRMWR_CHANNEL;

		result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
		kfree(wid.val);
		if (result != 0) {
			PRINT_ER(vif->ndev, "Failed to set remain channel\n");
			return -ENOMEM;
		}

		if (hif_drv->remain_on_ch.expired)
			hif_drv->remain_on_ch.expired(hif_drv->remain_on_ch.arg,
						      cookie);

		if (memcmp(hif_drv->assoc_bssid, null_bssid, ETH_ALEN) == 0)
			hif_drv->hif_state = HOST_IF_IDLE;
		else
			hif_drv->hif_state = HOST_IF_CONNECTED;
	} else {
		PRINT_D(GENERIC_DBG,  "Not in listen state\n");
	}

	return 0;
}

static void handle_listen_state_expired(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_vif *vif = msg->vif;
	struct wilc_remain_ch *hif_remain_ch = &msg->body.remain_on_ch;

	PRINT_INFO(HOSTINF_DBG, "CANCEL REMAIN ON CHAN\n");

	handle_roc_expired(vif, hif_remain_ch->cookie);

	kfree(msg);
}



static void listen_timer_cb(union sigval arg)
{

	struct host_if_drv *hif_drv = (struct host_if_drv *)arg.sival_ptr;

	struct wilc_vif *vif = hif_drv->remain_on_ch_timer_vif;
	int result;
	struct host_if_msg *msg;

	timer_delete(vif->hif_drv->remain_on_ch_timer);

	msg = wilc_alloc_work(vif, handle_listen_state_expired, false);
	if (!msg)
		return;

	msg->body.remain_on_ch.cookie = vif->hif_drv->remain_on_ch.cookie;

	result = wilc_enqueue_work(msg);
	if (result) {
		PRINT_ER(vif->ndev, "wilc_mq_send fail\n");
		kfree(msg);
	}
}




static void handle_set_mcast_filter(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	struct wilc_vif *vif = msg->vif;
	struct wilc_set_multicast *set_mc = &msg->body.mc_info;
	int result;
	struct wid wid;
	u8 *cur_byte;

	PRINT_INFO(HOSTINF_DBG, "Setup Multicast Filter\n");

	wid.id = WID_SETUP_MULTICAST_FILTER;
	wid.type = WID_BIN;
	wid.size = sizeof(struct wilc_set_multicast) + (set_mc->cnt * ETH_ALEN);
	wid.val = (s8*) create_ptr(wid.size);
	if (!wid.val)
		goto error;

	cur_byte = (u8 *)wid.val;
	put_unaligned_le32(set_mc->enabled, cur_byte);
	cur_byte += 4;

	put_unaligned_le32(set_mc->cnt, cur_byte);
	cur_byte += 4;

	if (set_mc->cnt > 0 && set_mc->mc_list)
		memcpy(cur_byte, set_mc->mc_list, set_mc->cnt * ETH_ALEN);

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to send setup multicast\n");

error:
	kfree(set_mc->mc_list);
	kfree(wid.val);
	kfree(msg);
}

void wilc_set_wowlan_trigger(struct wilc_vif *vif, u8 wowlan_trigger)
{
	int ret;
	struct wid wid;

	wid.id = WID_WOWLAN_TRIGGER;
	wid.type = WID_CHAR;
	wid.val = (s8*) &wowlan_trigger;
	wid.size = sizeof(s8);

	ret = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (ret)
		PRINT_ER(vif->ndev,
			 "Failed to send wowlan trigger config packet\n");
}

static void handle_scan_timer(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);
	int ret;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"handling scan timer\n");
	ret = handle_scan_done(msg->vif, SCAN_EVENT_ABORTED);
	if (ret)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to handle scan done\n");

	free_ptr(msg);
}

static void handle_scan_complete(struct work_struct *work)
{
	struct host_if_msg *msg = container_of(work, struct host_if_msg, work);

	timer_delete(msg->vif->hif_drv->scan_timer);
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"scan completed\n");

	handle_scan_done(msg->vif, SCAN_EVENT_DONE);

	free_ptr(msg);
}

static void timer_scan_cb(union sigval arg)
{

	struct host_if_drv *hif_drv = (struct host_if_drv *)arg.sival_ptr;

	struct wilc_vif *vif = hif_drv->scan_timer_vif;
	struct host_if_msg *msg;
	int result;

	msg = wilc_alloc_work(vif, handle_scan_timer, false);
	if (!msg)
		return;

	result = wilc_enqueue_work(msg);
	if (result)
		free_ptr(msg);
}


static void timer_connect_cb(union sigval arg)
{

	struct host_if_drv *hif_drv = (struct host_if_drv *)arg.sival_ptr;

	struct wilc_vif *vif = hif_drv->connect_timer_vif;
	struct host_if_msg *msg;
	int result;

	msg = wilc_alloc_work(vif, handle_connect_timeout, false);
	if (!msg)
		return;

	result = wilc_enqueue_work(msg);
	if (result)
		free_ptr(msg);
}


signed int wilc_send_buffered_eap(struct wilc_vif *vif,
				  void (*deliver_to_stack)(struct wilc_vif *,
							   u8 *, u32, u32, u8),
				  void (*eap_buf_param)(void *), u8 *buff,
				  unsigned int size, unsigned int pkt_offset,
				  void *user_arg)
{
	int result;
	struct host_if_msg *msg;
	fprintf(stderr, "[%s] In\n", __func__ );
	if (!vif || !deliver_to_stack || !eap_buf_param)
		return -EFAULT;

	msg = wilc_alloc_work(vif, handle_send_buffered_eap, false);
	if (!msg)
		return -EFAULT;
	msg->body.send_buff_eap.deliver_to_stack = deliver_to_stack;
	msg->body.send_buff_eap.eap_buf_param = eap_buf_param;
	msg->body.send_buff_eap.size = size;
	msg->body.send_buff_eap.pkt_offset = pkt_offset;
	msg->body.send_buff_eap.buff = create_ptr(size + pkt_offset);
	memcpy(msg->body.send_buff_eap.buff, buff, size + pkt_offset);
	msg->body.send_buff_eap.user_arg = user_arg;

	result = wilc_enqueue_work(msg);
	if (result) {
		PRINT_ER(vif->ndev, "enqueue work failed\n");
		kfree(msg->body.send_buff_eap.buff);
		kfree(msg);
	}
	return result;
}

int wilc_remove_wep_key(struct wilc_vif *vif, u8 index)
{
	struct wid wid;
	int result;

	wid.id = WID_REMOVE_WEP_KEY;
	wid.type = WID_STR;
	wid.size = sizeof(char);
	wid.val = (s8 *)&index;

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev,
			 "Failed to send remove wep key config packet\n");
	return result;
}


int wilc_set_wep_default_keyid(struct wilc_vif *vif, u8 index)
{
	struct wid wid;
	int result;

	wid.id = WID_KEY_ID;
	wid.type = WID_CHAR;
	wid.size = sizeof(char);
	wid.val = (s8 *)&index;
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev,
			 "Failed to send wep default key config packet\n");

	return result;
}

int wilc_add_wep_key_bss_sta(struct wilc_vif *vif, const u8 *key, u8 len,
			     u8 index)
{
	struct wid wid;
	int result;
	struct wilc_wep_key *wep_key;

	PRINT_INFO(HOSTINF_DBG, "Handling WEP key\n");
	wid.id = WID_ADD_WEP_KEY;
	wid.type = WID_STR;
	wid.size = sizeof(*wep_key) + len;
	wep_key = (struct wilc_wep_key *) create_ptr(wid.size);
	if (!wep_key) {
		PRINT_ER(vif->ndev, "No buffer to send Key\n");
		return -ENOMEM;
	}
	wid.val = (s8 *)wep_key;

	wep_key->index = index;
	wep_key->key_len = len;
	memcpy(wep_key->key, key, len);

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to add wep key config packet\n");


	kfree(wep_key);
	return result;
}

int wilc_add_wep_key_bss_ap(struct wilc_vif *vif, const u8 *key, u8 len,
			    u8 index, u8 mode, enum authtype auth_type)
{
	struct wid wid_list[3];
	int result;
	struct wilc_wep_key *wep_key;

	PRINT_INFO(HOSTINF_DBG, "Handling WEP key index: %d\n",
		   index);
	wid_list[0].id = WID_11I_MODE;
	wid_list[0].type = WID_CHAR;
	wid_list[0].size = sizeof(char);
	wid_list[0].val = (s8 *)&mode;

	wid_list[1].id = WID_AUTH_TYPE;
	wid_list[1].type = WID_CHAR;
	wid_list[1].size = sizeof(char);
	wid_list[1].val = (s8 *)&auth_type;

	wid_list[2].id = WID_WEP_KEY_VALUE;
	wid_list[2].type = WID_STR;
	wid_list[2].size = sizeof(*wep_key) + len;
	wep_key = (struct wilc_wep_key *) create_ptr(wid_list[2].size);
	if (!wep_key) {
		PRINT_ER(vif->ndev, "No buffer to send Key\n");
		return -ENOMEM;
	}

	wid_list[2].val = (s8 *)wep_key;

	wep_key->index = index;
	wep_key->key_len = len;
	memcpy(wep_key->key, key, len);
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, wid_list,
				      ARRAY_SIZE(wid_list));
	if (result)
		PRINT_ER(vif->ndev,
			 "Failed to add wep ap key config packet\n");

	kfree(wep_key);
	return result;
}


int wilc_add_ptk(struct wilc_vif *vif, const u8 *ptk, u8 ptk_key_len,
		 const u8 *mac_addr, const u8 *rx_mic, const u8 *tx_mic,
		 u8 mode, u8 cipher_mode, u8 index)
{
	slogf(_SLOGC_NETWORK, _SLOG_INFO, "[%s] In\n", __func__);
	int result = 0;
	u8 t_key_len = ptk_key_len + WILC_RX_MIC_KEY_LEN + WILC_TX_MIC_KEY_LEN;

	if (mode == WILC_AP_MODE) {
		struct wid wid_list[2];
		struct wilc_ap_wpa_ptk *key_buf;

		wid_list[0].id = WID_11I_MODE;
		wid_list[0].type = WID_CHAR;
		wid_list[0].size = sizeof(char);
		wid_list[0].val = (s8 *)&cipher_mode;

		key_buf = (struct wilc_ap_wpa_ptk *) create_ptr(sizeof(*key_buf) + t_key_len);
		if (!key_buf) {
			PRINT_ER(vif->ndev,
				 "NO buffer to keep Key buffer - AP\n");
			return -ENOMEM;
		}
		ether_addr_copy(key_buf->mac_addr, mac_addr);
		key_buf->index = index;
		key_buf->key_len = t_key_len;
		memcpy(&key_buf->key[0], ptk, ptk_key_len);

		if (rx_mic)
			memcpy(&key_buf->key[ptk_key_len], rx_mic,
			       WILC_RX_MIC_KEY_LEN);

		if (tx_mic)
			memcpy(&key_buf->key[ptk_key_len + WILC_RX_MIC_KEY_LEN],
			       tx_mic, WILC_TX_MIC_KEY_LEN);

		wid_list[1].id = WID_ADD_PTK;
		wid_list[1].type = WID_STR;
		wid_list[1].size = sizeof(*key_buf) + t_key_len;
		wid_list[1].val = (s8 *)key_buf;
		result = wilc_send_config_pkt(vif, WILC_SET_CFG, wid_list,
					      ARRAY_SIZE(wid_list));
		free_ptr(key_buf);
	} else if (mode == WILC_STATION_MODE) {
		struct wid wid;
		struct wilc_sta_wpa_ptk *key_buf;

		key_buf = (struct wilc_sta_wpa_ptk *) create_ptr(sizeof(*key_buf) + t_key_len);
		if (!key_buf) {
			PRINT_ER(vif->ndev,
				 "No buffer to keep Key buffer - Station\n");
			return -ENOMEM;
		}

		ether_addr_copy(key_buf->mac_addr, mac_addr);
		key_buf->key_len = t_key_len;
		memcpy(&key_buf->key[0], ptk, ptk_key_len);

		if (rx_mic)
			memcpy(&key_buf->key[ptk_key_len], rx_mic,
			       WILC_RX_MIC_KEY_LEN);

		if (tx_mic)
			memcpy(&key_buf->key[ptk_key_len + WILC_RX_MIC_KEY_LEN],
			       tx_mic, WILC_TX_MIC_KEY_LEN);

		wid.id = WID_ADD_PTK;
		wid.type = WID_STR;
		wid.size = sizeof(*key_buf) + t_key_len;
		wid.val = (s8 *)key_buf;
		result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
		free_ptr(key_buf);
	}

	return result;
}

int wilc_add_rx_gtk(struct wilc_vif *vif, const u8 *rx_gtk, u8 gtk_key_len,
		    u8 index, u32 key_rsc_len, const u8 *key_rsc,
		    const u8 *rx_mic, const u8 *tx_mic, u8 mode,
		    u8 cipher_mode)
{
	int result = 0;
	struct wilc_gtk_key *gtk_key;
	int t_key_len = gtk_key_len + WILC_RX_MIC_KEY_LEN + WILC_TX_MIC_KEY_LEN;

	slogf(_SLOGC_NETWORK, _SLOG_INFO, "[%s] In\n", __func__);

	gtk_key = (struct wilc_gtk_key *) create_ptr(sizeof(*gtk_key) + t_key_len);
	if (!gtk_key) {
		PRINT_ER(vif->ndev, "No buffer to send GTK Key\n");
		return -ENOMEM;
	}

	/* fill bssid value only in station mode */
	if (mode == WILC_STATION_MODE &&
	    vif->hif_drv->hif_state == HOST_IF_CONNECTED)
		memcpy(gtk_key->mac_addr, vif->hif_drv->assoc_bssid, ETH_ALEN);

	if (key_rsc)
		memcpy(gtk_key->rsc, key_rsc, 8);
	gtk_key->index = index;
	gtk_key->key_len = t_key_len;
	memcpy(&gtk_key->key[0], rx_gtk, gtk_key_len);

	if (rx_mic)
		memcpy(&gtk_key->key[gtk_key_len], rx_mic, WILC_RX_MIC_KEY_LEN);

	if (tx_mic)
		memcpy(&gtk_key->key[gtk_key_len + WILC_RX_MIC_KEY_LEN],
		       tx_mic, WILC_TX_MIC_KEY_LEN);

	if (mode == WILC_AP_MODE) {
		struct wid wid_list[2];

		wid_list[0].id = WID_11I_MODE;
		wid_list[0].type = WID_CHAR;
		wid_list[0].size = sizeof(char);
		wid_list[0].val = (s8 *)&cipher_mode;

		wid_list[1].id = WID_ADD_RX_GTK;
		wid_list[1].type = WID_STR;
		wid_list[1].size = sizeof(*gtk_key) + t_key_len;
		wid_list[1].val = (s8 *)gtk_key;

		result = wilc_send_config_pkt(vif, WILC_SET_CFG, wid_list,
					      ARRAY_SIZE(wid_list));
		free_ptr(gtk_key);
	} else if (mode == WILC_STATION_MODE) {
		struct wid wid;

		wid.id = WID_ADD_RX_GTK;
		wid.type = WID_STR;
		wid.size = sizeof(*gtk_key) + t_key_len;
		wid.val = (s8 *)gtk_key;
		result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
		free_ptr(gtk_key);
	}

	return result;
}

int wilc_set_pmkid_info(struct wilc_vif *vif, struct wilc_pmkid_attr *pmkid)
{
	struct wid wid;

	wid.id = WID_PMKID_INFO;
	wid.type = WID_STR;
	wid.size = (pmkid->numpmkid * sizeof(struct wilc_pmkid)) + 1;
	wid.val = (s8 *)pmkid;

	return wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
}

int wilc_get_mac_address(struct wilc_vif *vif, u8 *mac_addr)
{
	int result;
	struct wid wid;

	wid.id = WID_MAC_ADDR;
	wid.type = WID_STR;
	wid.size = ETH_ALEN;
	wid.val = (s8*) mac_addr;

	result = wilc_send_config_pkt(vif, WILC_GET_CFG, &wid, 1);
	if (result)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to get mac address\n");


	return result;
}

int wilc_set_mac_address(struct wilc_vif *vif, u8 *mac_addr)
{
	struct wid wid;
	int result;

	wid.id = WID_MAC_ADDR;
	wid.type = WID_STR;
	wid.size = ETH_ALEN;
	wid.val = (s8*) mac_addr;

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to set mac address\n");


	return result;
}

int wilc_set_join_req(struct wilc_vif *vif, u8 *bssid, const u8 *ies,
		      size_t ies_len)
{
	int result;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct wilc_conn_info *conn_info = &hif_drv->conn_info;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log1, ies_len = %d\n", __func__, ies_len);
	if (bssid)
		ether_addr_copy(conn_info->bssid, bssid);


	if (ies) {
		conn_info->req_ies_len = ies_len;
		conn_info->req_ies = create_ptr(ies_len);
		memcpy(conn_info->req_ies, ies, ies_len);
		//conn_info->req_ies = kmemdup(ies, ies_len, GFP_KERNEL);

		if (!conn_info->req_ies)
			return -ENOMEM;
	}
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log4\n", __func__);
	result = wilc_send_connect_wid(vif);
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log5\n", __func__);
	if (result) {
		PRINT_ER(vif->ndev, "Failed to send connect wid\n");
		goto free_ies;
	}

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] log6\n", __func__);
	hif_drv->connect_timer_vif = vif;

	struct itimerspec setting;
	setting.it_value.tv_sec = 9;
	setting.it_value.tv_nsec = 500000;
	timer_settime (hif_drv->connect_timer, 0, &setting, 0);

	return 0;

free_ies:
	kfree(conn_info->req_ies);

	return result;
}

int wilc_set_mac_chnl_num(struct wilc_vif *vif, u8 channel)
{
	struct wid wid;
	int result;

	wid.id = WID_CURRENT_CHANNEL;
	wid.type = WID_CHAR;
	wid.size = sizeof(char);
	wid.val = (s8 *)&channel;

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to set channel\n");

	return result;
}

int wilc_set_operation_mode(struct wilc_vif *vif, int index, u8 mode,
			    u8 ifc_id)
{
	struct wid wid;
	int result;
	struct wilc_drv_handler drv;


	wid.id = WID_SET_OPERATION_MODE;
	wid.type = WID_STR;
	wid.size = sizeof(drv);
	wid.val = (s8*) &drv;

	drv.handler = (u32) index;
	drv.mode = (ifc_id | (mode << 1));

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to set driver handler\n");


	return result;
}

s32 wilc_get_inactive_time(struct wilc_vif *vif, const u8 *mac, u32 *out_val)
{
	struct wid wid;
	s32 result;

	wid.id = WID_SET_STA_MAC_INACTIVE_TIME;
	wid.type = WID_STR;
	wid.size = ETH_ALEN;
	wid.val = (s8 *) create_ptr(wid.size);
	if (!wid.val) {
		PRINT_ER(vif->ndev, "Failed to allocate buffer\n");
		return -ENOMEM;
	}

	ether_addr_copy((uint8_t *)wid.val, mac);
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	kfree(wid.val);
	if (result) {
		PRINT_ER(vif->ndev, "Failed to set inactive mac\n");
		return result;
	}

	wid.id = WID_GET_INACTIVE_TIME;
	wid.type = WID_INT;
	wid.val = (s8 *)out_val;
	wid.size = sizeof(u32);
	result = wilc_send_config_pkt(vif, WILC_GET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to get inactive time\n");

	PRINT_INFO(CFG80211_DBG, "Getting inactive time : %d\n",
		   *out_val);

	return result;
}

int wilc_get_rssi(struct wilc_vif *vif, s8 *rssi_level)
{
	struct wid wid;
	int result;

	if (!rssi_level) {
		PRINT_ER(vif->ndev, "RSS pointer value is null\n");
		return -EFAULT;
	}

	wid.id = WID_RSSI;
	wid.type = WID_CHAR;
	wid.size = sizeof(char);
	wid.val = rssi_level;
	result = wilc_send_config_pkt(vif, WILC_GET_CFG, &wid, 1);
	if (result)
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"Failed to get RSSI value\n");

	return result;
}

int wilc_get_stats_async(struct wilc_vif *vif, struct rf_info *stats)
{
	int result;
	struct host_if_msg *msg;

	PRINT_INFO(HOSTINF_DBG, " getting async statistics\n");
	msg = wilc_alloc_work(vif, handle_get_statistics, false);
	if (!msg)
		return -EFAULT;

	msg->body.data = (char *)stats;

	result = wilc_enqueue_work(msg);
	if (result) {
		PRINT_ER(vif->ndev, "enqueue work failed\n");
		kfree(msg);
		return result;
	}

	return result;
}

int wilc_hif_set_cfg(struct wilc_vif *vif, struct cfg_param_attr *param)
{
	struct wid wid_list[4];
	int i = 0;

	if (param->flag & WILC_CFG_PARAM_RETRY_SHORT) {
		wid_list[i].id = WID_SHORT_RETRY_LIMIT;
		wid_list[i].val = (s8 *)&param->short_retry_limit;
		wid_list[i].type = WID_SHORT;
		wid_list[i].size = sizeof(u16);
		i++;
	}
	if (param->flag & WILC_CFG_PARAM_RETRY_LONG) {
		wid_list[i].id = WID_LONG_RETRY_LIMIT;
		wid_list[i].val = (s8 *)&param->long_retry_limit;
		wid_list[i].type = WID_SHORT;
		wid_list[i].size = sizeof(u16);
		i++;
	}
	if (param->flag & WILC_CFG_PARAM_FRAG_THRESHOLD) {
		wid_list[i].id = WID_FRAG_THRESHOLD;
		wid_list[i].val = (s8 *)&param->frag_threshold;
		wid_list[i].type = WID_SHORT;
		wid_list[i].size = sizeof(u16);
		i++;
	}
	if (param->flag & WILC_CFG_PARAM_RTS_THRESHOLD) {
		wid_list[i].id = WID_RTS_THRESHOLD;
		wid_list[i].val = (s8 *)&param->rts_threshold;
		wid_list[i].type = WID_SHORT;
		wid_list[i].size = sizeof(u16);
		i++;
	}

	return wilc_send_config_pkt(vif, WILC_SET_CFG, wid_list, i);
}



int wilc_init(struct wilc_vif *vif, struct host_if_drv **hif_drv_handler)
{
	struct host_if_drv *hif_drv;

	hif_drv = (struct host_if_drv *) create_ptr(sizeof(*hif_drv));
	if (!hif_drv) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"hif driver is NULL\n");
		return -ENOMEM;
	}
	*hif_drv_handler = hif_drv;
	vif->hif_drv = hif_drv;


	SIGEV_THREAD_INIT(&hif_drv->scan_timer_event, timer_scan_cb, hif_drv, 0);
	timer_create(CLOCK_REALTIME, &hif_drv->scan_timer_event, &hif_drv->scan_timer);

	SIGEV_THREAD_INIT(&hif_drv->connect_timer_event, timer_connect_cb, hif_drv, 0);
	timer_create(CLOCK_REALTIME, &hif_drv->connect_timer_event, &hif_drv->connect_timer);

	SIGEV_THREAD_INIT(&hif_drv->remain_on_ch_timer_event, listen_timer_cb, hif_drv, 0);
	timer_create(CLOCK_REALTIME, &hif_drv->remain_on_ch_timer_event, &hif_drv->remain_on_ch_timer);

	hif_drv->hif_state = HOST_IF_IDLE;
	hif_drv->p2p_timeout = 0;

	return 0;
}

int wilc_deinit(struct wilc_vif *vif)
{
	int result = 0;
	struct host_if_drv *hif_drv = vif->hif_drv;
	struct ifnet *ifp = vif->wilc->sc_ic.ic_ifp;

	if (!hif_drv) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"hif driver is NULL\n");
		return -EFAULT;
	}

	pthread_mutex_lock(&vif->wilc->deinit_lock);

	timer_delete(hif_drv->scan_timer);
	timer_delete(hif_drv->connect_timer);

	if (hif_drv->usr_scan_req.scan_result) {
		hif_drv->usr_scan_req.scan_result(SCAN_EVENT_ABORTED, NULL,
						  hif_drv->usr_scan_req.arg, ifp);
		hif_drv->usr_scan_req.scan_result = NULL;
	}

	hif_drv->hif_state = HOST_IF_IDLE;

	free_ptr(hif_drv);
	vif->hif_drv = NULL;

	pthread_mutex_unlock(&vif->wilc->deinit_lock);
	return result;
}


void wilc_network_info_received(struct wilc_dev *wilc, u8 *buffer, u32 length)
{
	int result;
	struct host_if_msg *msg;
	int id;
	struct host_if_drv *hif_drv;
	struct wilc_vif *vif;
	int srcu_idx;

	PRINT_D(GENERIC_DBG, "[%s] In\n", __func__);

	//id = get_unaligned_le32(&buffer[length - 4]);
	memcpy(&id, &buffer[length - 4], 4);
	srcu_idx = srcu_read_lock(&wilc->srcu);
	vif = wilc_get_vif_from_idx(wilc, id);
	if (!vif)
		goto out;

	hif_drv = vif->hif_drv;
	if (!hif_drv) {
		PRINT_ER(vif->ndev, "driver not init[%p]\n", hif_drv);
		goto out;
	}

	msg = wilc_alloc_work(vif, handle_rcvd_ntwrk_info, false);
	if (!msg)
		goto out;

	//msg->body.net_info.frame_len = get_unaligned_le16(&buffer[6]) - 1;
	memcpy(&(msg->body.net_info.frame_len), &buffer[6], 2);
	msg->body.net_info.frame_len -= 1;
	PRINT_D(GENERIC_DBG, "[%s] frame_len=%d\n", __func__, msg->body.net_info.frame_len);

	msg->body.net_info.rssi = buffer[8];
	msg->body.net_info.mgmt = (struct ieee80211_mgmt *) create_ptr(msg->body.net_info.frame_len);
	memcpy(msg->body.net_info.mgmt, &buffer[9], msg->body.net_info.frame_len);


	PRINT_D(GENERIC_DBG, "[%s] bssid=0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", __func__, msg->body.net_info.mgmt->bssid[0], msg->body.net_info.mgmt->bssid[1], msg->body.net_info.mgmt->bssid[2], msg->body.net_info.mgmt->bssid[3], msg->body.net_info.mgmt->bssid[4], msg->body.net_info.mgmt->bssid[5]);

	if (!msg->body.net_info.mgmt) {
		kfree(msg);
		goto out;
	}

	result = wilc_enqueue_work(msg);
	if (result) {
		PRINT_ER(vif->ndev, "message parameters (%d)\n", result);
		kfree(msg->body.net_info.mgmt);
		kfree(msg);
	}
out:
	srcu_read_unlock(&wilc->srcu, srcu_idx);
}

void wilc_gnrl_async_info_received(struct wilc_dev *wilc, uint8_t *buffer, uint32_t length)
{
	int result;
	struct host_if_msg *msg;
	int id;
	struct host_if_drv *hif_drv;
	struct wilc_vif *vif;
	int srcu_idx;

	pthread_mutex_lock(&wilc->deinit_lock);

	PRINT_INFO(HOSTINF_DBG, "[%s] In\n", __func__);
	//id = get_unaligned_le32(&buffer[length - 4]);
	memcpy(&id, &buffer[length - 4], 4);

	srcu_idx = srcu_read_lock(&wilc->srcu);
	vif = wilc_get_vif_from_idx(wilc, id);
	if (!vif)
		goto out;

	PRINT_INFO(HOSTINF_DBG, "[%s] General asynchronous info packet received\n", __func__);


	hif_drv = vif->hif_drv;

	if (!hif_drv) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"hif driver is NULL\n");
		goto out;
	}

	if (!hif_drv->conn_info.conn_result) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"there is no current Connect Request\n");
		goto out;
	}

	msg = wilc_alloc_work(vif, handle_rcvd_gnrl_async_info, false);
	if (!msg)
		goto out;

	msg->body.mac_info.status = buffer[7];
	PRINT_INFO(HOSTINF_DBG, "[%s] Received MAC status= %d Reason= %d Info = %d\n", __func__, buffer[7], buffer[8], buffer[9]);

	result = wilc_enqueue_work(msg);
	if (result) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"enqueue work failed\n");
		free_ptr(msg);
	}
out:
	pthread_mutex_unlock(&wilc->deinit_lock);
	srcu_read_unlock(&wilc->srcu, srcu_idx);
}

void wilc_scan_complete_received(struct wilc_dev *wilc, u8 *buffer, u32 length)
{
	int result;
	int id;
	struct host_if_drv *hif_drv;
	struct wilc_vif *vif;
	int srcu_idx;

	//id = get_unaligned_le32(&buffer[length - 4]);
	memcpy(&id, &buffer[length - 4], 4);
	srcu_idx = srcu_read_lock(&wilc->srcu);
	vif = wilc_get_vif_from_idx(wilc, id);
	if (!vif)
		goto out;

	PRINT_INFO(GENERIC_DBG, "Scan notification received\n");

	hif_drv = vif->hif_drv;
	if (!hif_drv) {
		PRINT_ER(vif->ndev, "hif driver is NULL\n");
		goto out;
	}

	if (hif_drv->usr_scan_req.scan_result) {
		struct host_if_msg *msg;

		msg = wilc_alloc_work(vif, handle_scan_complete, false);
		if (!msg)
			goto out;

		result = wilc_enqueue_work(msg);
		if (result) {
			PRINT_ER(vif->ndev, "enqueue work failed\n");
			kfree(msg);
		}
	}
out:
	srcu_read_unlock(&wilc->srcu, srcu_idx);
}

int wilc_remain_on_channel(struct wilc_vif *vif, u64 cookie,
			   u32 duration, u16 chan,
			   void (*expired)(void *, u64), void *user_arg)
{
	struct wilc_remain_ch roc;
	int result;

	PRINT_INFO(CFG80211_DBG, "called\n");
	roc.ch = chan;
	roc.expired = expired;
	roc.arg = user_arg;
	roc.duration = duration;
	roc.cookie = cookie;
	result = handle_remain_on_chan(vif, &roc);
	if (result)
		PRINT_ER(vif->ndev, "failed to set remain on channel\n");

	return result;
}

int wilc_listen_state_expired(struct wilc_vif *vif, u64 cookie)
{
	int result;
	struct host_if_drv *hif_drv = vif->hif_drv;

	if (!hif_drv) {
		PRINT_ER(vif->ndev, "hif driver is NULL\n");
		return -EFAULT;
	}

	timer_delete(hif_drv->remain_on_ch_timer);

	result = handle_roc_expired(vif, cookie);

	return result;
}

void wilc_frame_register(struct wilc_vif *vif, u16 frame_type, bool reg)
{
	struct wid wid;
	int result;
	struct wilc_reg_frame reg_frame;

	wid.id = WID_REGISTER_FRAME;
	wid.type = WID_STR;
	wid.size = sizeof(reg_frame);
	wid.val = (s8 *)&reg_frame;

	memset(&reg_frame, 0x0, sizeof(reg_frame));
	reg_frame.reg = reg;

	switch (frame_type) {
	case IEEE80211_STYPE_ACTION:
		PRINT_INFO(HOSTINF_DBG, "ACTION\n");
		reg_frame.reg_id = WILC_FW_ACTION_FRM_IDX;
		break;

	case IEEE80211_STYPE_PROBE_REQ:
		PRINT_INFO(HOSTINF_DBG, "PROBE REQ\n");
		reg_frame.reg_id = WILC_FW_PROBE_REQ_IDX;
		break;

	default:
		PRINT_INFO(HOSTINF_DBG, "Not valid frame type\n");
		break;
	}
	reg_frame.frame_type = cpu_to_le16(frame_type);
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to frame register\n");
}

int wilc_add_beacon(struct wilc_vif *vif, u32 interval, u32 dtim_period,
		    struct cfg80211_beacon_data *params)
{
	struct wid wid;
	int result;
	u8 *cur_byte;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting adding beacon\n");

	wid.id = WID_ADD_BEACON;
	wid.type = WID_BIN;
	wid.size = params->head_len + params->tail_len + 16;
	wid.val = (s8 *) create_ptr(wid.size);
	if (!wid.val) {
		PRINT_ER(vif->ndev, "Failed to allocate buffer\n");
		return -ENOMEM;
	}

	cur_byte = (u8 *)wid.val;
	put_unaligned_le32(interval, cur_byte);
	cur_byte += 4;
	put_unaligned_le32(dtim_period, cur_byte);
	cur_byte += 4;
	put_unaligned_le32(params->head_len, cur_byte);
	cur_byte += 4;

	if (params->head_len > 0)
		memcpy(cur_byte, params->head, params->head_len);
	cur_byte += params->head_len;

	put_unaligned_le32(params->tail_len, cur_byte);
	cur_byte += 4;

	if (params->tail_len > 0)
		memcpy(cur_byte, params->tail, params->tail_len);

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to send add beacon\n");

	kfree(wid.val);

	return result;
}

int wilc_del_beacon(struct wilc_vif *vif)
{
	int result;
	struct wid wid;
	u8 del_beacon = 0;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting deleting beacon message queue params\n");

	wid.id = WID_DEL_BEACON;
	wid.type = WID_CHAR;
	wid.size = sizeof(char);
	wid.val = (s8 *)&del_beacon;
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to send delete beacon\n");

	return result;
}

int wilc_add_station(struct wilc_vif *vif, const u8 *mac,
		     struct station_parameters *params)
{
	struct wid wid;
	int result;
	u8 *cur_byte;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting adding station message queue params\n");

	wid.id = WID_ADD_STA;
	wid.type = WID_BIN;
	wid.size = WILC_ADD_STA_LENGTH + params->supported_rates_len;
	wid.val = (s8 *) create_ptr(wid.size);
	if (!wid.val)
		return -ENOMEM;

	cur_byte = (u8 *)wid.val;
	wilc_hif_pack_sta_param(vif, cur_byte, mac, params);

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result != 0)
		PRINT_ER(vif->ndev, "Failed to send add station\n");

	kfree(wid.val);

	return result;
}

int wilc_del_station(struct wilc_vif *vif, const u8 *mac_addr)
{
	struct wid wid;
	int result;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting deleting station message queue params\n");

	wid.id = WID_REMOVE_STA;
	wid.type = WID_BIN;
	wid.size = ETH_ALEN;
	wid.val = (s8 *) create_ptr(wid.size);
	if (!wid.val) {
		PRINT_ER(vif->ndev, "Failed to allocate buffer\n");
		return -ENOMEM;
	}

	if (!mac_addr)
		eth_broadcast_addr((u8 *)wid.val);
	else
		ether_addr_copy((uint8_t *)wid.val, mac_addr);

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to del station\n");

	kfree(wid.val);

	return result;
}

int wilc_del_allstation(struct wilc_vif *vif, u8 mac_addr[][ETH_ALEN])
{
	struct wid wid;
	int result;
	int i;
	u8 assoc_sta = 0;
	struct wilc_del_all_sta del_sta;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting deauthenticating station message queue params\n");
	memset(&del_sta, 0x0, sizeof(del_sta));
	for (i = 0; i < WILC_MAX_NUM_STA; i++) {
		if (!is_zero_ether_addr(mac_addr[i])) {
			PRINT_INFO(CFG80211_DBG, "BSSID = %x%x%x%x%x%x\n",
				   mac_addr[i][0], mac_addr[i][1],
				   mac_addr[i][2], mac_addr[i][3],
				   mac_addr[i][4], mac_addr[i][5]);
			assoc_sta++;
			ether_addr_copy(del_sta.mac[i], mac_addr[i]);
		}
	}
	if (!assoc_sta) {
		PRINT_INFO(CFG80211_DBG, "NO ASSOCIATED STAS\n");
		return 0;
	}
	del_sta.assoc_sta = assoc_sta;

	wid.id = WID_DEL_ALL_STA;
	wid.type = WID_STR;
	wid.size = (assoc_sta * ETH_ALEN) + 1;
	wid.val = (s8 *)&del_sta;

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to send delete all station\n");

	return result;
}

int wilc_edit_station(struct wilc_vif *vif, const u8 *mac,
		      struct station_parameters *params)
{
	struct wid wid;
	int result;
	u8 *cur_byte;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting editing station message queue params\n");

	wid.id = WID_EDIT_STA;
	wid.type = WID_BIN;
	wid.size = WILC_ADD_STA_LENGTH + params->supported_rates_len;
	wid.val = (s8 *) create_ptr(wid.size);
	if (!wid.val)
		return -ENOMEM;

	cur_byte = (u8 *)wid.val;
	wilc_hif_pack_sta_param(vif, cur_byte, mac, params);

	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to send edit station\n");

	kfree(wid.val);
	return result;
}

int wilc_set_power_mgmt(struct wilc_vif *vif, bool enabled, u32 timeout)
{
	struct wid wid;
	int result;
	s8 power_mode;

	PRINT_INFO(HOSTINF_DBG, "\n\n>> Setting PS to %d <<\n\n",
		   enabled);
	if (enabled)
		power_mode = WILC_FW_MIN_FAST_PS;
	else
		power_mode = WILC_FW_NO_POWERSAVE;

	wid.id = WID_POWER_MANAGEMENT;
	wid.val = &power_mode;
	wid.size = sizeof(char);
	result = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (result)
		PRINT_ER(vif->ndev, "Failed to send power management\n");

	return result;
}

int wilc_setup_multicast_filter(struct wilc_vif *vif, u32 enabled, u32 count,
				u8 *mc_list)
{
	int result;
	struct host_if_msg *msg;

	PRINT_INFO(HOSTINF_DBG,
		   "Setting Multicast Filter params\n");
	msg = wilc_alloc_work(vif, handle_set_mcast_filter, false);
	if (!msg)
		return -EFAULT;

	msg->body.mc_info.enabled = enabled;
	msg->body.mc_info.cnt = count;
	msg->body.mc_info.mc_list = mc_list;

	result = wilc_enqueue_work(msg);
	if (result) {
		PRINT_ER(vif->ndev, "enqueue work failed\n");
		kfree(msg);
	}
	return result;
}

int wilc_set_tx_power(struct wilc_vif *vif, u8 tx_power)
{
	struct wid wid;

	wid.id = WID_TX_POWER;
	wid.type = WID_CHAR;
	wid.val = (s8 *)&tx_power;
	wid.size = sizeof(char);

	return wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
}

int wilc_get_tx_power(struct wilc_vif *vif, u8 *tx_power)
{
	struct wid wid;

	wid.id = WID_TX_POWER;
	wid.type = WID_CHAR;
	wid.val = (s8 *)tx_power;
	wid.size = sizeof(char);

	return wilc_send_config_pkt(vif, WILC_GET_CFG, &wid, 1);
}

bool is_valid_gpio(struct wilc_vif *vif, u8 gpio)
{
	switch (vif->wilc->chip) {
	case WILC_1000:
		if (gpio == 0 || gpio == 1 || gpio == 4 || gpio == 6)
			return true;
		else
			return false;
	case WILC_3000:
		if (gpio == 0 || gpio == 3 || gpio == 4 ||
		    (gpio >= 17 && gpio <= 20))
			return true;
		else
			return false;
	default:
		return false;
	}
}

int wilc_set_antenna(struct wilc_vif *vif, u8 mode)
{
	struct wid wid;
	int ret;
	struct sysfs_attr_group *attr_syfs_p = &vif->wilc->attr_sysfs;
	struct host_if_set_ant set_ant;

	set_ant.mode = mode;

	if (attr_syfs_p->ant_swtch_mode == ANT_SWTCH_INVALID_GPIO_CTRL) {
		PRINT_ER(vif->ndev, "Ant switch GPIO mode is invalid.\n");
		PRINT_ER(vif->ndev, "Set it using /sys/wilc/ant_swtch_mode\n");
		return WILC_FAIL;
	}

	if (is_valid_gpio(vif, attr_syfs_p->antenna1)) {
		set_ant.antenna1 = attr_syfs_p->antenna1;
	} else {
		PRINT_ER(vif->ndev, "Invalid GPIO %d\n", attr_syfs_p->antenna1);
		return WILC_FAIL;
	}

	if (attr_syfs_p->ant_swtch_mode == ANT_SWTCH_DUAL_GPIO_CTRL) {
		if ((attr_syfs_p->antenna2 != attr_syfs_p->antenna1) &&
		    is_valid_gpio(vif, attr_syfs_p->antenna2)) {
			set_ant.antenna2 = attr_syfs_p->antenna2;
		} else {
			PRINT_ER(vif->ndev, "Invalid GPIO %d\n",
				 attr_syfs_p->antenna2);
			return WILC_FAIL;
		}
	}

	set_ant.gpio_mode = attr_syfs_p->ant_swtch_mode;

	wid.id = WID_ANTENNA_SELECTION;
	wid.type = WID_BIN;
	wid.val = (s8 *)&set_ant;
	wid.size = sizeof(struct host_if_set_ant);
	if (attr_syfs_p->ant_swtch_mode == ANT_SWTCH_SNGL_GPIO_CTRL)
	{
		PRINT_INFO(CFG80211_DBG,
			   "set antenna %d on GPIO %d\n", set_ant.mode,
			   set_ant.antenna1);
	}
	else if (attr_syfs_p->ant_swtch_mode == ANT_SWTCH_DUAL_GPIO_CTRL)
		PRINT_INFO(CFG80211_DBG,
			   "set antenna %d on GPIOs %d and %d\n",
			   set_ant.mode, set_ant.antenna1,
			   set_ant.antenna2);


	ret = wilc_send_config_pkt(vif, WILC_SET_CFG, &wid, 1);
	if (ret)
		PRINT_ER(vif->ndev, "Failed to set antenna mode\n");

	return ret;
}



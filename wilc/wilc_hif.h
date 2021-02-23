/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */


#ifndef WILC_HIF_H
#define WILC_HIF_H

#include <sys/cdefs_bsd.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "wilc_wlan_if.h"
#include <sys/siginfo.h>
#include <signal.h>
#include <type_defs.h>
#include "wilc_main.h"
#include "cfg80211.h"

enum {
	WILC_IDLE_MODE = 0x0,
	WILC_AP_MODE = 0x1,
	WILC_STATION_MODE = 0x2,
	WILC_GO_MODE = 0x3,
	WILC_CLIENT_MODE = 0x4,
	WILC_MONITOR_MODE = 0x5
};

#define WILC_MAX_NUM_STA			9
#define WILC_MAX_NUM_SCANNED_CH			14
#define WILC_MAX_NUM_PROBED_SSID		10

#define WILC_TX_MIC_KEY_LEN			8
#define WILC_RX_MIC_KEY_LEN			8

#define WILC_MAX_NUM_PMKIDS			16
#define WILC_ADD_STA_LENGTH			40
#define WILC_NUM_CONCURRENT_IFC			2

enum {
	WILC_SET_CFG = 0,
	WILC_GET_CFG
};

#define WILC_MAX_ASSOC_RESP_FRAME_SIZE   256
extern uint32_t cfg_packet_timeout;

struct assoc_resp {
	//__le16 capab_info;
	//__le16 status_code;
	//__le16 aid;
	uint16_t capab_info;
	uint16_t status_code;
	uint16_t aid;
} __packed;


struct rf_info {
	uint8_t link_speed;
	int8_t rssi;
	uint32_t tx_cnt;
	uint32_t rx_cnt;
	uint32_t tx_fail_cnt;
};

enum host_if_state {
	HOST_IF_IDLE			= 0,
	HOST_IF_SCANNING		= 1,
	HOST_IF_CONNECTING		= 2,
	HOST_IF_WAITING_CONN_RESP	= 3,
	HOST_IF_CONNECTED		= 4,
	HOST_IF_P2P_LISTEN		= 5,
	HOST_IF_FORCE_32BIT		= 0xFFFFFFFF
};

#define WLAN_PMKID_LEN			16
#define ETH_ALEN				6
struct wilc_pmkid {
	uint8_t bssid[ETH_ALEN];
	uint8_t pmkid[WLAN_PMKID_LEN];
} __packed;

struct wilc_pmkid_attr {
	uint8_t numpmkid;
	struct wilc_pmkid pmkidlist[WILC_MAX_NUM_PMKIDS];
} __packed;

struct cfg_param_attr {
	uint32_t flag;
	uint16_t short_retry_limit;
	uint16_t long_retry_limit;
	uint16_t frag_threshold;
	uint16_t rts_threshold;
};

enum cfg_param {
	WILC_CFG_PARAM_RETRY_SHORT = 1, //BIT(0)
	WILC_CFG_PARAM_RETRY_LONG = 2, //BIT(1),
	WILC_CFG_PARAM_FRAG_THRESHOLD = 4, //BIT(2),
	WILC_CFG_PARAM_RTS_THRESHOLD = 8 //BIT(3)
};

enum scan_event {
	SCAN_EVENT_NETWORK_FOUND	= 0,
	SCAN_EVENT_DONE			= 1,
	SCAN_EVENT_ABORTED		= 2,
	SCAN_EVENT_FORCE_32BIT		= 0xFFFFFFFF
};

enum conn_event {
	EVENT_CONN_RESP		= 0,
	EVENT_DISCONN_NOTIF	= 1,
	EVENT_FORCE_32BIT		= 0xFFFFFFFF
};

enum {
	WILC_HIF_SDIO = 0,
	WILC_HIF_SPI = 1, //BIT(0)
	WILC_HIF_SDIO_GPIO_IRQ = 2, //BIT(1)
};

enum {
	WILC_MAC_STATUS_INIT = -1,
	WILC_MAC_STATUS_DISCONNECTED = 0,
	WILC_MAC_STATUS_CONNECTED = 1
};

struct wilc_rcvd_net_info {
	int8_t rssi;
	uint8_t ch;
	uint16_t frame_len;
	struct ieee80211_mgmt *mgmt;
};

typedef void (*wilc_remain_on_chan_ready)(void *);

struct wilc_user_scan_req {
	void (*scan_result)(enum scan_event evt,
			    struct wilc_rcvd_net_info *info, void *priv, struct ifnet *ifp);
	void *arg;
	uint32_t ch_cnt;
};

struct wilc_conn_info {
	uint8_t bssid[ETH_ALEN];
	uint8_t security;
	enum authtype auth_type;
	uint8_t ch;
	uint8_t *req_ies;
	size_t req_ies_len;
	struct host_if_msg *resp_ies;
	uint16_t resp_ies_len;
	uint16_t status;
	void (*conn_result)(enum conn_event evt, uint8_t status, void *priv);
	void *arg;
	void *param;
};

struct wilc_remain_ch {
	uint16_t ch;
	uint32_t duration;
	void (*expired)(void *priv, uint64_t cookie);
	void *arg;
	uint64_t cookie;
};

struct host_if_drv {
	struct wilc_user_scan_req usr_scan_req;
	struct wilc_conn_info conn_info;
	struct wilc_remain_ch remain_on_ch;
	uint64_t p2p_timeout;

	enum host_if_state hif_state;

	uint8_t assoc_bssid[ETH_ALEN];
	int comp_test_key_block;
	int comp_test_disconn_block;
	int comp_get_rssi;
	int comp_inactive_time;

	///struct timer_list scan_timer;
	struct itimerspec timerSpec_scan_timer;
	struct sigevent scan_timer_event;
	timer_t scan_timer;
	struct wilc_vif *scan_timer_vif;

	//struct timer_list connect_timer;
	struct itimerspec timerSpec_connect_timer;
	struct sigevent connect_timer_event;
	timer_t connect_timer;


	struct wilc_vif *connect_timer_vif;

	///struct timer_list remain_on_ch_timer;
	struct itimerspec timerSpec_remain_on_ch_timer;
	struct sigevent remain_on_ch_timer_event;
	timer_t remain_on_ch_timer;
	struct wilc_vif *remain_on_ch_timer_vif;

	bool ifc_up;
	uint8_t assoc_resp[WILC_MAX_ASSOC_RESP_FRAME_SIZE];
};

int wilc_set_join_req(struct wilc_vif *vif, u8 *bssid, const u8 *ies, size_t ies_len);
void wilc_gnrl_async_info_received(struct wilc_dev *wilc, uint8_t *buffer, uint32_t length);
int wilc_scan(struct wilc_vif *vif, u8 scan_source, u8 scan_type,
	      u8 *ch_freq_list, u8 ch_list_len,
	      void (*scan_result_fn)(enum scan_event,
	    		  struct wilc_rcvd_net_info *, void *, struct ifnet *),
	      void *user_arg, struct cfg80211_scan_request *request);
int wilc_init(struct wilc_vif *vif, struct host_if_drv **hif_drv_handler);
int wilc_set_operation_mode(struct wilc_vif *vif, int index, u8 mode, u8 ifc_id);
int wilc_get_vif_idx(struct wilc_vif *vif);
int wilc_get_mac_address(struct wilc_vif *vif, u8 *mac_addr);
void handle_connect_cancel(struct wilc_vif *vif);
int wilc_deinit(struct wilc_vif *vif);
void wilc_network_info_received(struct wilc_dev *wilc, u8 *buffer, u32 length);
void wilc_scan_complete_received(struct wilc_dev *wilc, u8 *buffer, u32 length);
const u8 *cfg80211_find_ie(u8 eid, const u8 *ies, int len);

#endif

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef WILC_WFI_NETDEVICE
#define WILC_WFI_NETDEVICE

#include <stdbool.h>
#include <inttypes.h>
#include <mqueue.h>
#include "wilc_wlan.h"
#include "wilc_wlan_if.h"
#include "wilc_wlan_cfg.h"
#include "wilc_hif.h"
#include "wilc_utilities.h"
#include "ieee80211.h"

#define NUM_REG_FRAME				2


#define FLOW_CTRL_LOW_THRESHLD		128
#define FLOW_CTRL_UP_THRESHLD		256

#define WILC_MAX_NUM_PMKIDS			16
#define PMKID_FOUND				1
#define NUM_STA_ASSOCIATED			8

#define NUM_REG_FRAME				2

#define TCP_ACK_FILTER_LINK_SPEED_THRESH	54
#define DEFAULT_LINK_SPEED			72

#define GET_PKT_OFFSET(a) (((a) >> 22) & 0x1ff)

#define ANT_SWTCH_INVALID_GPIO_CTRL		0
#define ANT_SWTCH_SNGL_GPIO_CTRL		1
#define ANT_SWTCH_DUAL_GPIO_CTRL		2

struct wilc_wfi_stats {
	unsigned long rx_packets;
	unsigned long tx_packets;
	unsigned long rx_bytes;
	unsigned long tx_bytes;
	uint64_t rx_time;
	uint64_t tx_time;
};

struct wilc_wfi_key {
	uint8_t *key;
	uint8_t *seq;
	int key_len;
	int seq_len;
	uint32_t cipher;
};

struct wilc_wfi_wep_key {
	uint8_t *key;
	uint8_t key_len;
	uint8_t key_idx;
};

struct sta_info {
	uint8_t sta_associated_bss[WILC_MAX_NUM_STA][ETH_ALEN];
};

/*Parameters needed for host interface for  remaining on channel*/
struct wilc_wfi_p2p_listen_params {
	struct ieee80211_channel *listen_ch;
	uint32_t listen_duration;
	uint64_t listen_cookie;
};

/* Struct to buffer eapol 1/4 frame */
struct wilc_buffered_eap {
	unsigned int size;
	unsigned int pkt_offset;
	uint8_t *buff;
};

struct wilc_p2p_var {
	uint8_t local_random;
	uint8_t recv_random;
	bool is_wilc_ie;
};


static const uint32_t wilc_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC
};

#define IEEE80211_BAND_2GHZ 	NL80211_BAND_2GHZ
#define CHAN2G(_channel, _freq, _flags) {       \
	.band             = IEEE80211_BAND_2GHZ, \
	.center_freq      = (_freq),             \
	.hw_value         = (_channel),          \
	.flags            = (_flags),            \
	.max_antenna_gain = 0,                   \
	.max_power        = 30,                  \
}

struct ieee80211_channel_linux {
	enum nl80211_band band;
	uint32_t center_freq;
	uint16_t hw_value;
	uint32_t flags;
	int max_antenna_gain;
	int max_power;
};


static const struct ieee80211_channel_linux wilc_2ghz_channels[] = {
	CHAN2G(1,  2412, 0),
	CHAN2G(2,  2417, 0),
	CHAN2G(3,  2422, 0),
	CHAN2G(4,  2427, 0),
	CHAN2G(5,  2432, 0),
	CHAN2G(6,  2437, 0),
	CHAN2G(7,  2442, 0),
	CHAN2G(8,  2447, 0),
	CHAN2G(9,  2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0)
};

#define RATETAB_ENT(_rate, _hw_value, _flags) {        \
	.bitrate  = (_rate),                    \
	.hw_value = (_hw_value),                \
	.flags    = (_flags),                   \
}

struct ieee80211_rate_linux {
	uint32_t flags;
	uint16_t bitrate;
	uint16_t hw_value, hw_value_short;
};

#if 0
static struct ieee80211_rate_linux wilc_bitrates[] = {
	RATETAB_ENT(10,  0,  0),
	RATETAB_ENT(20,  1,  0),
	RATETAB_ENT(55,  2,  0),
	RATETAB_ENT(110, 3,  0),
	RATETAB_ENT(60,  9,  0),
	RATETAB_ENT(90,  6,  0),
	RATETAB_ENT(120, 7,  0),
	RATETAB_ENT(180, 8,  0),
	RATETAB_ENT(240, 9,  0),
	RATETAB_ENT(360, 10, 0),
	RATETAB_ENT(480, 11, 0),
	RATETAB_ENT(540, 12, 0)
};
#endif

struct wilc_priv {
	///struct wireless_dev wdev;
	struct cfg80211_scan_request *scan_req;
	struct wilc_wfi_p2p_listen_params remain_on_ch_params;
	uint64_t tx_cookie;
	bool cfg_scanning;
	uint8_t associated_bss[ETH_ALEN];
	struct sta_info assoc_stainfo;
	struct sk_buff *skb;
	struct net_device *dev;	//TODO:need to remove it
	struct host_if_drv *hif_drv;
	struct wilc_pmkid_attr pmkid_list;
	uint8_t wep_key[4][WLAN_KEY_LEN_WEP104];
	uint8_t wep_key_len[4];
	/* The real interface that the monitor is on */
	struct net_device *real_ndev;
	struct wilc_wfi_key *wilc_gtk[WILC_MAX_NUM_STA];
	struct wilc_wfi_key *wilc_ptk[WILC_MAX_NUM_STA];
	uint8_t wilc_groupkey;

	pthread_mutex_t scan_req_lock;

	struct wilc_buffered_eap *buffered_eap;

	///struct timer_list eap_buff_timer;
	struct itimerspec timerSpec_eap_buff_timer;
	struct sigevent eap_buff_timer_event;
	timer_t eap_buff_timer;

	int scanned_cnt;
	struct wilc_p2p_var p2p;
	uint64_t inc_roc_cookie;
};

struct frame_reg {
	uint16_t type;
	bool reg;
};

#define MAX_TCP_SESSION                25
#define MAX_PENDING_ACKS               256

struct ack_session_info {
	uint32_t seq_num;
	uint32_t bigger_ack_num;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t status;
};

struct pending_acks {
	uint32_t ack_num;
	uint32_t session_index;
	struct txq_entry_t  *txqe;
};

struct tcp_ack_filter {
	struct ack_session_info ack_session_info[2 * MAX_TCP_SESSION];
	struct pending_acks pending_acks[MAX_PENDING_ACKS];
	uint32_t pending_base;
	uint32_t tcp_session;
	uint32_t pending_acks_idx;
	bool enabled;
};




struct net_device_stats {
	unsigned long	rx_packets;
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_bytes;
	unsigned long	rx_errors;
	unsigned long	tx_errors;
	unsigned long	rx_dropped;
	unsigned long	tx_dropped;
	unsigned long	multicast;
	unsigned long	collisions;
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;
	unsigned long	rx_crc_errors;
	unsigned long	rx_frame_errors;
	unsigned long	rx_fifo_errors;
	unsigned long	rx_missed_errors;
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};

struct wilc_vif {
	uint8_t idx;
	uint8_t iftype;
	int monitor_flag;
	int mac_opened;
	struct frame_reg frame_reg[NUM_REG_FRAME];
	struct net_device_stats netstats;
	struct wilc_dev *wilc;
	uint8_t bssid[ETH_ALEN];
	struct host_if_drv *hif_drv;
	struct net_device *ndev;

	struct rf_info periodic_stats;

	///struct timer_list periodic_rssi;
	struct itimerspec timerSpec_periodic_rssi;
	struct sigevent periodic_rssi_event;
	timer_t periodic_rssi;

	struct tcp_ack_filter ack_filter;
	bool connecting;
	struct wilc_priv priv;
	struct list_head list;
	uint8_t restart;
	bool p2p_listen_state;
	//struct cfg80211_bss *bss;
};


//FIXME
#if 0
struct wilc {


	const struct wilc_hif_func *hif_func;
	int io_type;
	int8_t mac_status;

	int gpio_irq;

	bool initialized;
	int dev_irq_num;
	int close;
	uint8_t vif_num;
	///struct wilc_vif *vif[NUM_CONCURRENT_IFC];
	uint8_t open_ifcs;
	/*protect head of transmit queue*/
	///struct mutex txq_add_to_head_cs;
	/*protect txq_entry_t transmit queue*/
	///spinlock_t txq_spinlock;
	/*protect rxq_entry_t receiver queue*/
	///struct mutex rxq_cs;
	/* lock to protect hif access */
	///struct mutex hif_cs;

	///struct completion cfg_event;
	///struct completion sync_event;
	///struct completion txq_event;
	///struct completion txq_thread_started;
	///struct completion debug_thread_started;
	///struct task_struct *txq_thread;
	///struct task_struct *debug_thread;

	int quit;
	int cfg_frame_in_use;
	///struct wilc_cfg_frame cfg_frame;
	uint32_t cfg_frame_offset;
	int cfg_seq_no;

	uint8_t *rx_buffer;
	uint32_t rx_buffer_offset;
	uint8_t *tx_buffer;

	struct txq_handle txq[NQUEUES];
	int txq_entries;

	struct rxq_entry_t rxq_head;

	///const struct firmware *firmware;

	///struct device *dev;
	///struct device *dt_dev;

	enum wilc_chip_type chip;

	uint8_t power_status[DEV_MAX];
	uint8_t keep_awake[DEV_MAX];
	///struct mutex cs;
	int clients_count;
	struct workqueue_struct *hif_workqueue;

	//struct wilc_cfg cfg;
	void *bus_data;
};
#endif


#endif

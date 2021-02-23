// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef WILC_MAIN_H
#define WILC_MAIN_H

//#include <sys/device.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <sys/io-pkt.h>
#include <io-pkt/iopkt_driver.h>
#include <net80211/ieee80211_var.h>
#include <stdio.h>
#include <proto.h>
#include <pthread.h>
//#include "wilc_wlan.h"
//#include "wilc_wlan_cfg.h"
#include "wilc_utilities.h"
#include "list.h"


#define NQUEUES			4
#define MAX_SCAN_AP		25
#define MAX_SSID_LEN	32
#define BSSID_LEN		6

struct pkt_buf	{
	struct list_head list;
	int	size;
	uint8_t *buf;

};

struct wilc_dev {
	struct device		sc_dev;	/* common device */
	struct ethercom		sc_ec;	/* common ethernet */
	struct ieee80211com	sc_ic;	/* common 80211 */
	nic_config_t		cfg;	/* nic information */
	/* whatever else you need follows */
	struct _iopkt_self	*sc_iopkt;
	int			sc_iid;
	int			sc_irq;
	int			sc_intr_cnt;
	int			sc_intr_spurious;
	struct _iopkt_inter	sc_inter;
	void			*sc_sdhook;
	u_int		sc_flags;
	int 		chip;
	FILE		*fw_file;
	sdio_ext_t*	sdio;
	const struct wilc_hif_func *hif_func;
	void *bus_data;
	int io_type;
	bool initialized;
	int quit;
	int8_t mac_status;
	int cfg_seq_no;
	uint32_t cfg_frame_offset;
	pthread_t irq_tid;
	pthread_mutex_t			rx_mutex;
	int				rx_full;
	struct ifqueue			rx_queue;
	struct pkt_buf			rx_q;

	struct wilc_cfg wilc_cfg;
	struct wilc_cfg_frame cfg_frame;
	struct txq_handle txq[NQUEUES];

	uint8_t *rx_buffer;
	uint32_t rx_buffer_offset;
	uint8_t *tx_buffer;

	struct rxq_entry_t rxq_head;

	/*protect vif list queue*/
	pthread_mutex_t vif_mutex;
	uint8_t open_ifcs;
	/*protect head of transmit queue*/
	pthread_mutex_t txq_add_to_head_cs;
	/*protect txq_entry_t transmit queue*/
	pthread_spinlock_t txq_spinlock;
	/*protect rxq_entry_t receiver queue*/
	pthread_mutex_t rxq_cs;
	/* lock to protect hif access */
	pthread_mutex_t hif_cs;
	/* lock to protect issue of wid command to fw */
	pthread_mutex_t cfg_cmd_lock;
	/* deinit lock */
	pthread_mutex_t deinit_lock;

	pthread_mutex_t cs;

	//completion signal
	int cfg_event;
	int sync_event;
	pthread_mutex_t txq_event_mutex;
	pthread_cond_t txq_event;
	int txq_thread_started;
	pthread_mutex_t debug_thread_started_mutex;
	pthread_cond_t debug_thread_started; //FIXME

	struct list_head vif_list;
	struct workqueue_struct *hif_workqueue;

	int txq_entries;
	pthread_t txq_thread;
	int txq_nw;
	int close;
	uint8_t sta_ch;
	uint8_t vif_num;

	struct sysfs_attr_group attr_sysfs;

};

struct channel
{
	uint16_t freq;
	uint16_t flags;
};

struct scan_results
{
	uint8_t ssid[MAX_SSID_LEN];	// ssid name
	uint8_t ssid_len;
	uint8_t bssid[BSSID_LEN];	// bssid
	uint8_t channel;
	int8_t rssi;
	uint16_t frame_len;
	struct ieee80211_mgmt *mgmt;

};


#endif



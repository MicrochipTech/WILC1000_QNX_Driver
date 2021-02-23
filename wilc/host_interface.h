/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef HOST_INT_H
#define HOST_INT_H


#define IDLE_MODE	0x00
#define AP_MODE		0x01
#define STATION_MODE	0x02
#define GO_MODE		0x03
#define CLIENT_MODE	0x04
#define MONITOR_MODE	0x05

#define ACTION		0xD0
#define PROBE_REQ	0x40
#define PROBE_RESP	0x50

#define P2P_IFC		0x00
#define WLAN_IFC	0x01
#define DEFAULT_IFC	0x03

#define IFC_0 "wlan0"
#define IFC_1 "p2p0"

#define ACTION_FRM_IDX				0
#define PROBE_REQ_IDX				1
#define MAX_NUM_STA				9
#define ACTIVE_SCAN_TIME			10
#define PASSIVE_SCAN_TIME			1200
#define MIN_SCAN_TIME				10
#define MAX_SCAN_TIME				1200
#define DEFAULT_SCAN				0
#define USER_SCAN				BIT(0)
#define OBSS_PERIODIC_SCAN			BIT(1)
#define OBSS_ONETIME_SCAN			BIT(2)
#define GTK_RX_KEY_BUFF_LEN			24
#define ADDKEY					0x1
#define REMOVEKEY				0x2
#define DEFAULTKEY				0x4
#define ADDKEY_AP				0x8
#define MAX_NUM_SCANNED_NETWORKS		100
#define MAX_NUM_SCANNED_NETWORKS_SHADOW		130
#define MAX_NUM_PROBED_SSID			10
#define CHANNEL_SCAN_TIME			250

#define TX_MIC_KEY_LEN				8
#define RX_MIC_KEY_LEN				8
#define PTK_KEY_LEN				16

#define TX_MIC_KEY_MSG_LEN			26
#define RX_MIC_KEY_MSG_LEN			48
#define PTK_KEY_MSG_LEN				39

#define PMKSA_KEY_LEN				22
#define ETH_ALEN				6
#define PMKID_LEN				16
#define WILC_MAX_NUM_PMKIDS			16
#define WILC_ADD_STA_LENGTH			40
#define NUM_CONCURRENT_IFC			2
#define DRV_HANDLER_SIZE			5
#define DRV_HANDLER_MASK			0x000000FF

#define NUM_RSSI                5

#define SET_CFG              0
#define GET_CFG              1

#define MAX_ASSOC_RESP_FRAME_SIZE   256

#endif

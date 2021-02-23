/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */


#ifndef NM_WFI_CFGOPERATIONS
#define NM_WFI_CFGOPERATIONS
#include "wilc_wfi_netdevice.h"
#include "ieee80211.h"
#include "type_defs.h"
#include "cfg80211.h"



struct wiphy {
  u8 perm_addr[ETH_ALEN];
  u8 addr_mask[ETH_ALEN];
};



int wilc_wfi_p2p_rx(struct wilc_vif *vif, u8 *buff, u32 size);
void cfg_connect_result(enum conn_event conn_disconn_evt,u8 mac_status, void *priv_data);
void wilc_wlan_set_bssid(struct wilc_vif *vif, u8 *bssid, u8 mode);


struct wilc_vif *wilc_get_wl_to_vif(struct wilc_dev *wl);
int wilc_init_host_int(struct wilc_vif *vif);
void wilc_deinit_host_int(struct wilc_vif *vif);
void wlan_deinit_locks(struct wilc_dev *wl);
int wilc_cfg80211_init(struct wilc_dev *wilc, int io_type, const struct wilc_hif_func *ops);
void wlan_init_locks(struct wilc_dev *wl);
int scan(struct wilc_vif *vif, struct cfg80211_scan_request *request);

#endif

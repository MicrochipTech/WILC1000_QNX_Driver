// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef WILC_NETDEV_H
#define WILC_NETDEV_H

extern int wait_for_recovery;

static inline void ether_addr_copy(uint8_t *dst, const uint8_t *src)
{

	uint16_t *a = (uint16_t *)dst;
	const uint16_t *b = (const uint16_t *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];

}



static inline bool ether_addr_equal_unaligned(const u8 *addr1, const u8 *addr2)
{

	return memcmp(addr1, addr2, ETH_ALEN) == 0;
}


void wilc_mac_indicate(struct wilc_dev *wilc);
void wilc_wlan_set_bssid(struct wilc_vif *vif, u8 *bssid, u8 mode);
int wlan_initialize_threads(struct wilc_dev *wilc);
int wilc_mac_open(struct wilc_vif *vif, unsigned char mac_add[]);
void wilc_netdev_cleanup(struct wilc_dev *wilc);
struct wilc_vif *wilc_netdev_ifc_init(struct wilc_dev *wl, const char *name,
				      int iftype, enum nl80211_iftype type,
				      bool rtnl_locked);
void wilc_wfi_mgmt_rx(struct wilc_dev *wilc, u8 *buff, u32 size);
void wilc_frmw_to_host(struct wilc_vif *vif, u8 *buff, u32 size,
		       u32 pkt_offset, u8 status);

#endif

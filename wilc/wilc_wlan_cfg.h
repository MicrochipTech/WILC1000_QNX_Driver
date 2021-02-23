/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef WILC_WLAN_CFG_H
#define WILC_WLAN_CFG_H

#include <inttypes.h>
#include "list.h"
#include "wilc_main.h"
#include "wilc_wfi_netdevice.h"
#include "wilc_utilities.h"



struct wilc_dev;

int cfg_init(struct wilc_dev *wl);
void cfg_deinit(struct wilc_dev *wl);
int cfg_get_val(struct wilc_dev *wl, uint16_t wid, uint8_t *buffer, uint32_t buffer_size);
//int cfg_set(struct wilc_vif *vif, int start, uint16_t wid, uint8_t *buffer, uint32_t buffer_size, int commit, uint32_t drv_handler);

void cfg_indicate_rx(struct wilc_dev *wilc, uint8_t *frame, int size, struct wilc_cfg_rsp *rsp);
int cfg_set_wid(struct wilc_vif *vif, uint8_t *frame, uint32_t offset, uint16_t id, uint8_t *buf,
			  int size);
int cfg_get_wid(uint8_t *frame, uint32_t offset, uint16_t id);
#endif

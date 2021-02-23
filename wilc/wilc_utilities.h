// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef WILC_UTILITIES
#define WILC_UTILITIES

#include <inttypes.h>
#include "list.h"

#define WILC_MAX_CFG_FRAME_SIZE		1468

struct rxq_entry_t {
	struct list_head list;
	uint8_t *buffer;
	int buffer_size;
};

struct wilc_cfg_cmd_hdr {
	uint8_t cmd_type;
	uint8_t seq_no;
	//__le16 total_len;
	uint16_t	total_len;
	//__le32 driver_handler;
	uint32_t driver_handler;
};


struct wilc_cfg_frame {
	struct wilc_cfg_cmd_hdr hdr;
	uint8_t frame[WILC_MAX_CFG_FRAME_SIZE];
};

struct txq_entry_t {
	struct list_head list;
	int type;
	uint8_t q_num;
	int ack_idx;
	uint8_t *buffer;
	int buffer_size;
	void *priv;
	int status;
	struct wilc_vif *vif;
	void (*tx_complete_func)(void *priv, int status);
};

struct txq_handle {
	struct txq_entry_t txq_head;
	uint16_t count;
	uint8_t acm;
};


/////////////

struct wilc_cfg_byte {
	uint16_t id;
	uint8_t val;
};

struct wilc_cfg_hword {
	uint16_t id;
	uint16_t val;
};

struct wilc_cfg_word {
	uint32_t id;
	uint32_t val;
};

struct wilc_cfg_str {
	uint16_t id;
	uint8_t *str;
};

struct wilc_cfg_bin {
	uint16_t id;
	uint8_t *bin;
};

struct wilc_cfg_str_vals {
	uint8_t mac_address[7];
	uint8_t firmware_version[129];
	uint8_t assoc_rsp[256];
};

struct wilc_bin_vals {
	uint8_t antenna_param[5];
};

struct wilc_cfg {
	struct wilc_cfg_byte *b;
	struct wilc_cfg_hword *hw;
	struct wilc_cfg_word *w;
	struct wilc_cfg_str *s;
	struct wilc_cfg_str_vals *str_vals;
	struct wilc_cfg_bin *bin;
	struct wilc_bin_vals *bin_vals;
};


struct sysfs_attr_group {
	bool p2p_mode;
	uint8_t ant_swtch_mode;
	uint8_t antenna1;
	uint8_t antenna2;
};

///


void* create_ptr(size_t size);
void free_ptr(void* ptr);
void kfree(void* ptr);

#endif

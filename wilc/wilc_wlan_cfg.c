// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#include "wilc_wlan_cfg.h"
#include "wilc_wlan_if.h"
#include <inttypes.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/slogcodes.h>
#include <wilc_wfi_netdevice.h>
#include "unaligned.h"


enum cfg_cmd_type {
	CFG_BYTE_CMD	= 0,
	CFG_HWORD_CMD	= 1,
	CFG_WORD_CMD	= 2,
	CFG_STR_CMD	= 3,
	CFG_BIN_CMD	= 4
};

static struct wilc_cfg_byte g_cfg_byte[] = {
	{WID_STATUS, 0},
	{WID_RSSI, 0},
	{WID_LINKSPEED, 0},
	{WID_TX_POWER, 0},
	{WID_WOWLAN_TRIGGER, 0},
	{WID_NIL, 0}
};

static struct wilc_cfg_hword g_cfg_hword[] = {
	{WID_NIL, 0}
};

static struct wilc_cfg_word g_cfg_word[] = {
	{WID_FAILED_COUNT, 0},
	{WID_RECEIVED_FRAGMENT_COUNT, 0},
	{WID_SUCCESS_FRAME_COUNT, 0},
	{WID_GET_INACTIVE_TIME, 0},
	{WID_NIL, 0}

};

static struct wilc_cfg_str g_cfg_str[] = {
	{WID_FIRMWARE_VERSION, NULL},
	{WID_MAC_ADDR, NULL},
	{WID_ASSOC_RES_INFO, NULL},
	{WID_NIL, NULL}
};

static struct wilc_cfg_bin g_cfg_bin[] = {
	{WID_ANTENNA_SELECTION, NULL},
	{WID_NIL, NULL}
};

/********************************************
 *
 *      Configuration Functions
 *
 ********************************************/

static int wilc_wlan_cfg_set_byte(uint8_t *frame, uint32_t offset, uint16_t id, uint8_t val8)
{

	if ((offset + 4) >= WILC_MAX_CFG_FRAME_SIZE)
		return 0;

	put_unaligned_le16(id, &frame[offset]);
	put_unaligned_le16(1, &frame[offset + 2]);
	frame[offset + 4] = val8;
	return 5;
}

static int wilc_wlan_cfg_set_hword(uint8_t *frame, uint32_t offset, uint16_t id, uint16_t val16)
{
	if ((offset + 5) >= WILC_MAX_CFG_FRAME_SIZE)
		return 0;

	put_unaligned_le16(id, &frame[offset]);
	put_unaligned_le16(2, &frame[offset + 2]);
	put_unaligned_le16(val16, &frame[offset + 4]);
	return 6;
}

static int wilc_wlan_cfg_set_word(uint8_t *frame, uint32_t offset, uint16_t id, uint32_t val32)
{
	if ((offset + 7) >= WILC_MAX_CFG_FRAME_SIZE)
		return 0;

	put_unaligned_le16(id, &frame[offset]);
	put_unaligned_le16(4, &frame[offset + 2]);
	put_unaligned_le32(val32, &frame[offset + 4]);
	return 8;
}

static int wilc_wlan_cfg_set_str(uint8_t *frame, uint32_t offset, uint16_t id, uint8_t *str,
			uint32_t size)
{
	if ((offset + size + 4) >= WILC_MAX_CFG_FRAME_SIZE)
		return 0;

	put_unaligned_le16(id, &frame[offset]);
	put_unaligned_le16(size, &frame[offset + 2]);

	if (str && size != 0)
		memcpy(&frame[offset + 4], str, size);

	return (size + 4);
}

static int wilc_wlan_cfg_set_bin(uint8_t *frame, uint32_t offset, uint16_t id, uint8_t *b, uint32_t size)
{
	uint32_t i;
	uint8_t checksum = 0;

	if ((offset + size + 5) >= WILC_MAX_CFG_FRAME_SIZE)
		return 0;

	put_unaligned_le16(id, &frame[offset]);
	put_unaligned_le16(size, &frame[offset + 2]);

	if ((b) && size != 0) {
		memcpy(&frame[offset + 4], b, size);
		for (i = 0; i < size; i++)
			checksum += frame[offset + i + 4];
	}

	frame[offset + size + 4] = checksum;
	return (size + 5);
}

/********************************************
 *
 *      Configuration Response Functions
 *
 ********************************************/

#define GET_WID_TYPE(wid)		(((wid) >> 12) & 0x7)
static void wilc_wlan_parse_response_frame(struct wilc_dev *wl, uint8_t *info,
					   int size)
{
	uint16_t wid;
	uint32_t len = 0, i = 0;

	while (size > 0) {
		i = 0;
		///wid = get_unaligned_le16(info);
		memcpy (&wid, info, 2);

		switch (GET_WID_TYPE(wid)) {
		case WID_CHAR:
			do {
				if (wl->wilc_cfg.b[i].id == WID_NIL)
					break;

				if (wl->wilc_cfg.b[i].id == wid) {
					wl->wilc_cfg.b[i].val = info[4];
					break;
				}
				i++;
			} while (1);
			len = 3;
			break;

		case WID_SHORT:
			do {
				struct wilc_cfg_hword *hw = &wl->wilc_cfg.hw[i];

				if (hw->id == WID_NIL)
					break;

				if (hw->id == wid) {
					//hw->val = get_unaligned_le16(&info[4]);
					memcpy(&(hw->val), &info[4], 2);
					break;
				}
				i++;
			} while (1);
			len = 4;
			break;

		case WID_INT:
			do {
				struct wilc_cfg_word *w = &wl->wilc_cfg.w[i];

				if (w->id == WID_NIL)
					break;

				if (w->id == wid) {
					//w->val = get_unaligned_le32(&info[4]);
					memcpy(&(w->val), &info[4], 4);
					break;
				}
				i++;
			} while (1);
			len = 6;
			break;

		case WID_STR:
			do {
				if (wl->wilc_cfg.s[i].id == WID_NIL)
					break;

				if (wl->wilc_cfg.s[i].id == wid) {
					memcpy(wl->wilc_cfg.s[i].str, &info[2],
					       (2+((info[3] << 8) | info[2])));
					break;
				}
				i++;
			} while (1);
			len = 2+((info[3] << 8) | info[2]);
			break;
		case WID_BIN_DATA:
			do {
				uint16_t length = (info[3] << 8) | info[2];
				uint8_t checksum = 0;
				int j = 0;

				if (wl->wilc_cfg.bin[i].id == WID_NIL)
					break;

				if (wl->wilc_cfg.bin[i].id != wid) {
					i++;
					continue;
				}

				/*
				 * Compute the Checksum of received
				 * data field
				 */
				for (j = 0; j < length; j++)
					checksum += info[4 + j];
				/*
				 * Verify the checksum of recieved BIN
				 * DATA
				 */
				if (checksum != info[4 + length]) {
					slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: Checksum Failed\n", __func__);
					return;
				}

				memcpy(wl->wilc_cfg.bin[i].bin, &info[2], length+2);
				/*
				 * value length + data length +
				 * checksum
				 */
				len = 2 + length + 1;
				break;

			} while (1);
			break;
		default:
			break;
		}
		size -= (2 + len);
		info += (2 + len);
	}
}

static void wilc_wlan_parse_info_frame(struct wilc_dev *wl, uint8_t *info)
{
	uint32_t wid, len;

	//wid = get_unaligned_le16(info);
	memcpy(&wid, info, 2);

	len = info[2];

	if (len == 1 && wid == WID_STATUS) {
		int i = 0;

		do {
			if (wl->wilc_cfg.b[i].id == WID_NIL)
				break;

			if (wl->wilc_cfg.b[i].id == wid) {
				wl->wilc_cfg.b[i].val = info[3];
				break;
			}
			i++;
		} while (1);
	}
}

/********************************************
 *
 *      Configuration Exported Functions
 *
 ********************************************/

int cfg_set_wid(struct wilc_vif *vif, uint8_t *frame, uint32_t offset, uint16_t id, uint8_t *buf,
			  int size)
{
	uint8_t type = (id >> 12) & 0xf;
	int ret = 0;

	switch (type) {
	case CFG_BYTE_CMD:
		if (size >= 1)
			ret = wilc_wlan_cfg_set_byte(frame, offset, id, *buf);
		break;

	case CFG_HWORD_CMD:
		if (size >= 2)
			ret = wilc_wlan_cfg_set_hword(frame, offset, id,
						      *((uint16_t *)buf));
		break;

	case CFG_WORD_CMD:
		if (size >= 4)
			ret = wilc_wlan_cfg_set_word(frame, offset, id,
						     *((uint32_t *)buf));
		break;

	case CFG_STR_CMD:
		ret = wilc_wlan_cfg_set_str(frame, offset, id, buf, size);
		break;

	case CFG_BIN_CMD:
		ret = wilc_wlan_cfg_set_bin(frame, offset, id, buf, size);
		break;
	default:
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: illegal id\n", __func__);
	}

	return ret;
}

int cfg_get_wid(uint8_t *frame, uint32_t offset, uint16_t id)
{
	if ((offset + 2) >= WILC_MAX_CFG_FRAME_SIZE)
		return 0;

	put_unaligned_le16(id, &frame[offset]);
	return 2;
}


int cfg_get_val(struct wilc_dev *wl, uint16_t wid, uint8_t *buffer, uint32_t buffer_size)
{
	uint32_t type = (wid >> 12) & 0xf;
	int i, ret = 0;
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: In, type =0x%x\n", __func__, type);
	i = 0;
	if (type == CFG_BYTE_CMD) {
		do {
			if (wl->wilc_cfg.b[i].id == WID_NIL)
				break;

			if (wl->wilc_cfg.b[i].id == wid) {
				memcpy(buffer,  &wl->wilc_cfg.b[i].val, 1);
				ret = 1;
				break;
			}
			i++;
		} while (1);
	} else if (type == CFG_HWORD_CMD) {
		do {
			if (wl->wilc_cfg.hw[i].id == WID_NIL)
				break;

			if (wl->wilc_cfg.hw[i].id == wid) {
				memcpy(buffer,  &wl->wilc_cfg.hw[i].val, 2);
				ret = 2;
				break;
			}
			i++;
		} while (1);
	} else if (type == CFG_WORD_CMD) {
		do {
			if (wl->wilc_cfg.w[i].id == WID_NIL)
				break;

			if (wl->wilc_cfg.w[i].id == wid) {
				memcpy(buffer,  &wl->wilc_cfg.w[i].val, 4);
				ret = 4;
				break;
			}
			i++;
		} while (1);
	} else if (type == CFG_STR_CMD) {
		do {
			uint32_t id = wl->wilc_cfg.s[i].id;

			if (id == WID_NIL)
				break;

			if (id == wid) {
				//uint16_t size = get_unaligned_le16(wl->wilc_cfg.s[i].str);
				uint16_t size;
				memcpy(&size, wl->wilc_cfg.s[i].str, 2);

				if (buffer_size >= size) {
					memcpy(buffer,  &wl->wilc_cfg.s[i].str[2],
					       size);
					ret = size;
				}
				break;
			}
			i++;
		} while (1);
	} else if (type == CFG_BIN_CMD) { /* binary command */
		do {
			if (wl->wilc_cfg.bin[i].id == WID_NIL)
				break;

			if (wl->wilc_cfg.bin[i].id == wid) {
				uint32_t size = wl->wilc_cfg.bin[i].bin[0] |
					     (wl->wilc_cfg.bin[i].bin[1]<<8);
				if (buffer_size >= size) {
					memcpy(buffer, &wl->wilc_cfg.bin[i].bin[2],
					       size);
					ret = size;
				}
				break;
			}
			i++;
		} while (1);
	} else {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[CFG]: illegal type (%08x)\n", wid);
	}
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s: Out\n", __func__);

	return ret;
}
void cfg_indicate_rx(struct wilc_dev *wilc, uint8_t *frame, int size,
		     struct wilc_cfg_rsp *rsp)
{
	PRINT_D(RX_DBG, "%s: In\n", __func__);
	uint8_t msg_type;
	uint8_t msg_id;

	msg_type = frame[0];
	msg_id = frame[1];      /* seq no */
	frame += 4;
	size -= 4;
	rsp->type = 0;

	/*
	 * The valid types of response messages are
	 * 'R' (Response),
	 * 'I' (Information), and
	 * 'N' (Network Information)
	 */
	//fprintf(stderr, "[cfg_indicate_rx] log1\r\n");
	switch (msg_type) {
	case 'R':
		PRINT_INFO(RX_DBG, "%s: R\n", __func__);
		wilc_wlan_parse_response_frame(wilc, frame, size);
		rsp->type = WILC_CFG_RSP;
		rsp->seq_no = msg_id;
		break;

	case 'I':
		PRINT_INFO(RX_DBG, "%s: I\n", __func__);
		wilc_wlan_parse_info_frame(wilc, frame);
		rsp->type = WILC_CFG_RSP_STATUS;
		rsp->seq_no = msg_id;
		/*call host interface info parse as well*/
		PRINT_INFO(RX_DBG, "%s: Info message received\n", __func__);
		wilc_gnrl_async_info_received(wilc, frame - 4, size + 4);
		break;

	case 'N':
		PRINT_INFO(RX_DBG, "%s: N\n", __func__);
		PRINT_INFO(RX_DBG, "%s: New Network Notification Received\n", __func__);
		wilc_network_info_received(wilc, frame - 4, size + 4);
		break;

	case 'S':
		PRINT_INFO(RX_DBG, "%s: Scan Notification Received\n", __func__);
		wilc_scan_complete_received(wilc, frame - 4, size + 4);
		break;

	default:
		fprintf(stderr, "[cfg_indicate_rx] log2, unknown message\r\n");
		PRINT_INFO(RX_DBG, "%s: unknown message\n", __func__);
		PRINT_INFO(RX_DBG, "%s: Receive unknown message 0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n", __func__, frame[0], frame[1], frame[2], frame[3],frame[4], frame[5], frame[6], frame[7]);
		rsp->seq_no = msg_id;
		break;
	}

	PRINT_D(RX_DBG, "%s: Out\n", __func__);
}

int cfg_init(struct wilc_dev *wl)
{
	struct wilc_cfg_str_vals *str_vals;
	struct wilc_bin_vals *bin_vals;
	int i = 0;

	wl->wilc_cfg.b = (struct wilc_cfg_byte *) create_ptr(sizeof(g_cfg_byte));
	if (!wl->wilc_cfg.b)
		return -1;
	memcpy(wl->wilc_cfg.b, g_cfg_byte, sizeof(g_cfg_byte));

	wl->wilc_cfg.hw = (struct wilc_cfg_hword *) create_ptr(sizeof(g_cfg_hword));
	if (!wl->wilc_cfg.hw)
		goto out_b;
	memcpy(wl->wilc_cfg.hw, g_cfg_hword, sizeof(g_cfg_hword));

	wl->wilc_cfg.w = (struct wilc_cfg_word *) create_ptr(sizeof(g_cfg_word));
	if (!wl->wilc_cfg.w)
		goto out_hw;
	memcpy(wl->wilc_cfg.w, g_cfg_word, sizeof(g_cfg_word));

	wl->wilc_cfg.s = (struct wilc_cfg_str *) create_ptr(sizeof(g_cfg_str));
	if (!wl->wilc_cfg.s)
		goto out_w;
	memcpy(wl->wilc_cfg.s, g_cfg_str, sizeof(g_cfg_str));

	str_vals = (struct wilc_cfg_str_vals *) create_ptr(sizeof(*str_vals));
	if (!str_vals)
		goto out_s;


	wl->wilc_cfg.bin = (struct wilc_cfg_bin *) create_ptr(sizeof(g_cfg_bin));
	if (!wl->wilc_cfg.bin)
		goto out_str_val;
	memcpy(wl->wilc_cfg.bin, g_cfg_bin, sizeof(g_cfg_bin));

	bin_vals = (struct wilc_bin_vals *) create_ptr(sizeof(*bin_vals));
	if (!bin_vals)
		goto out_bin;

	/* store the string cfg parameters */
	wl->wilc_cfg.str_vals = str_vals;
	wl->wilc_cfg.s[i].id = WID_FIRMWARE_VERSION;
	wl->wilc_cfg.s[i].str = str_vals->firmware_version;
	i++;
	wl->wilc_cfg.s[i].id = WID_MAC_ADDR;
	wl->wilc_cfg.s[i].str = str_vals->mac_address;
	i++;
	wl->wilc_cfg.s[i].id = WID_ASSOC_RES_INFO;
	wl->wilc_cfg.s[i].str = str_vals->assoc_rsp;
	i++;
	wl->wilc_cfg.s[i].id = WID_NIL;
	wl->wilc_cfg.s[i].str = NULL;

	/* store the bin parameters */
	i = 0;
	wl->wilc_cfg.bin[i].id = WID_ANTENNA_SELECTION;
	wl->wilc_cfg.bin[i].bin = bin_vals->antenna_param;
	i++;

	wl->wilc_cfg.bin[i].id = WID_NIL;
	wl->wilc_cfg.bin[i].bin = NULL;

	return 0;

out_bin:
	free_ptr(wl->wilc_cfg.bin);
out_str_val:
	free_ptr(str_vals);
out_s:
	free_ptr(wl->wilc_cfg.s);
out_w:
	free_ptr(wl->wilc_cfg.w);
out_hw:
	free_ptr(wl->wilc_cfg.hw);
out_b:
	free_ptr(wl->wilc_cfg.b);
	return -1;
}

void cfg_deinit(struct wilc_dev *wl)
{
	free_ptr(wl->wilc_cfg.b);
	free_ptr(wl->wilc_cfg.hw);
	free_ptr(wl->wilc_cfg.w);
	free_ptr(wl->wilc_cfg.s);
	free_ptr(wl->wilc_cfg.str_vals);
	free_ptr(wl->wilc_cfg.bin);
	free_ptr(wl->wilc_cfg.bin_vals);
}

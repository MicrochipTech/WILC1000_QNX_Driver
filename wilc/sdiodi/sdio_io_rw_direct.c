/*
 * $QNXLicenseC:
 * Copyright 2009, QNX Software Systems.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not reproduce, modify or distribute this software except in
 * compliance with the License. You may obtain a copy of the License
 * at: http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OF ANY KIND, either express or implied.
 *
 * This file may contain contributions from others, either as
 * contributors under the License or as licensors under other terms.
 * Please review this entire file for other proprietary rights or license
 * notices, as well as the QNX Development Suite License Guide at
 * http://licensing.qnx.com/license-guide/ for other information.
 * $
 */

#include <sys/slog.h>
#include <sys/slogcodes.h>
#include "proto.h"

static int sdio_send_cmd52(sdio_ext_t *sdio, uint32_t cmdarg, uint8_t *resp)
{
	sdio_cmd_t	cmd;
	int			i;

	for (i = 0; i < 5; i++) {
		cmd.opcode  = 52;
		cmd.rsptype = SDIO_RSP_R5;
		cmd.eflags  = SDMMC_CMD_INTR;
		cmd.argument = cmdarg;
		if (sdio_send_command(sdio, &cmd) == MMC_SUCCESS)
			break;
	}

	if (i >= 5)
	{
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s i>5 \n", __func__);
		return (SDIO_FAILURE);
	}
	if (((cmd.resp[0] & 0xCB00) != 0) || ((cmd.resp[0] & 0x3000) == 0))
	{
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"%s response wrong, resp = 0x%x  \n", __func__, cmd.resp[0]);
		return (SDIO_FAILURE);
	}
	if (resp)
		*resp = (uint8_t)cmd.resp[0];

	return (SDIO_SUCCESS);
}

int	sdio_write_ioreg(void *hdl, uint8_t fn, int reg, uint8_t data)
{
	return sdio_send_cmd52(hdl, MAKE_SDIO_OFFSET(reg) | MAKE_SDIO_FUNCTION(fn) | MAKE_SDIO_DIR(1) | data, NULL);
}

int	sdio_read_ioreg(void *hdl, uint8_t fn, int reg, uint8_t *data)
{
	return sdio_send_cmd52(hdl, MAKE_SDIO_OFFSET(reg) | MAKE_SDIO_FUNCTION(fn), data);
}

int	sdio_set_ioreg(void *hdl, uint8_t fn, int reg, uint8_t bits)
{
	uint8_t	data;

	if (sdio_send_cmd52(hdl, MAKE_SDIO_OFFSET(reg) | MAKE_SDIO_FUNCTION(fn), &data) != SDIO_SUCCESS)
		return (SDIO_FAILURE);

	return sdio_send_cmd52(hdl, MAKE_SDIO_OFFSET(reg) | MAKE_SDIO_FUNCTION(fn) | MAKE_SDIO_DIR(1) | data | bits, NULL);
}

int	sdio_clr_ioreg(void *hdl, uint8_t fn, int reg, uint8_t bits)
{
	uint8_t	data;

	if (sdio_send_cmd52(hdl, MAKE_SDIO_OFFSET(reg) | MAKE_SDIO_FUNCTION(fn), &data) != SDIO_SUCCESS)
		return (SDIO_FAILURE);

	return sdio_send_cmd52(hdl, MAKE_SDIO_OFFSET(reg) | MAKE_SDIO_FUNCTION(fn) | MAKE_SDIO_DIR(1) | (data & ~bits), NULL);
}


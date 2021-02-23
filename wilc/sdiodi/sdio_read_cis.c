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

#include "proto.h"


int sdio_read_cis(sdio_ext_t *sdio, uint8_t func, uint8_t cistpl, uint8_t *buf, int *len)
{
	uint32_t	cis, i, j;
	uint8_t		result, tuple_len, tuple_end, tuple;

	if (sdio_cmd52_read(sdio, SDIO_FN_CIS_POINTER_0_REG(func), 0, &result) != SDIO_SUCCESS)
		return SDIO_FAILURE;
	cis = result;

	if (sdio_cmd52_read(sdio, SDIO_FN_CIS_POINTER_1_REG(func), 0, &result) != SDIO_SUCCESS)
		return SDIO_FAILURE;
	cis |= result << 8;

	if (sdio_cmd52_read(sdio, SDIO_FN_CIS_POINTER_2_REG(func), 0, &result) != SDIO_SUCCESS)
		return SDIO_FAILURE;
	cis |= result << 16;

	if (cis == 0)
		return SDIO_FAILURE;

	// Search for CISTPL
	i = j = 0;
	result = tuple_end = tuple_len = 0;
	while (result != SDIO_CISTPL_END) {
		if (sdio_cmd52_read(sdio, cis + j, func, &tuple) != SDIO_SUCCESS)
			return SDIO_FAILURE;
		++j;
		result = tuple;

		if ((tuple != SDIO_CISTPL_VERS_1) && 
						(tuple != SDIO_CISTPL_MANFID) &&
						(tuple != SDIO_CISTPL_FUNCID) &&
						(tuple != SDIO_CISTPL_FUNCE) &&
						(tuple != SDIO_CISTPL_END))
			continue;

		if (sdio_cmd52_read(sdio, cis + j, func, &tuple_len) != SDIO_SUCCESS)
			return SDIO_FAILURE;
		++j;

		if (tuple != 0x00 && tuple != 0xFF)
			tuple_end = j + tuple_len;

		if (tuple == cistpl) {
			switch (cistpl) {
				case SDIO_CISTPL_VERS_1:
					j += 2;
					i = 0;
					while (j < tuple_end && i < *len - 1) {
						if (sdio_cmd52_read(sdio, cis + j, func, &result) != SDIO_SUCCESS)
							return SDIO_FAILURE;
						j++;
						buf[i++] = (result == 0 ? ' ' : result);
					}
					i -= 3;
					buf[i] = 0;
					*len = i;
					return (SDIO_SUCCESS);
					break;
				case SDIO_CISTPL_MANFID:
				case SDIO_CISTPL_FUNCID:
				case SDIO_CISTPL_FUNCE:
					i = 0;
					while (j <= tuple_end && i < *len) {
						if (sdio_cmd52_read(sdio, cis + j, func, &result) != SDIO_SUCCESS)
							return SDIO_FAILURE;
						j++;
						buf[i++] = result;
					}
					*len = i;
					return (SDIO_SUCCESS);
					break;
			}
			return SDIO_SUCCESS;
		} else
			j = tuple_end;

	}

	return (SDIO_SUCCESS);
}


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

#include "proto.h"
int sdio_set_blksz(void	*hdl, int func, int blksz)
{

	uint8_t		reg;
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	// Config block size
	if (sdio_write_ioreg(sdio, 0, SDIO_FN_BLOCK_SIZE_0_REG(func), blksz & 0xFF) != SDIO_SUCCESS)
	{
		sdio_slogf(0,"warning: sdio_set_blksz: failed at calling sdio_write_ioreg, with blksz=%d, func=%d\n\r",blksz,func);
		sdio_slogf(0, "sdio_set_blksz : Failed in CMD52 writing the first byte of block size to set block size for function %d", func);
		return (SDIO_FAILURE);
	}

	if (sdio_read_ioreg(sdio, 0, SDIO_FN_BLOCK_SIZE_0_REG(func), &reg) != SDIO_SUCCESS)
	{
		sdio_slogf(0,"warning: sdio_set_blksz: failed at calling sdio_read_ioreg, with reg=0x%x, func=%d\n\r",reg, func);
		sdio_slogf(0,  "sdio_set_blksz : Failed in CMD52 back reading the first byte of block size been set for function %d", func);
		return (SDIO_FAILURE);
	}

	if (reg != (blksz & 0xFF))
	{
		sdio_slogf(0,"warning: sdio_set_blksz: failed with reg=0x%x, blksz=%d\n\r",reg,blksz);
		sdio_slogf(0, "sdio_set_blksz : Back read value %d of the first byte of block size is different from written value %d", reg, blksz & 0xFF);
		return (SDIO_FAILURE);
	}

	if (sdio_write_ioreg(sdio, 0, SDIO_FN_BLOCK_SIZE_1_REG(func), blksz >> 8) != SDIO_SUCCESS)
	{
		sdio_slogf(0,"warning: sdio_set_blksz: failed at calling sdio_write_ioreg, with (blksz>>8)=%d, func=%d\n\r",(blksz>>8),func);
		sdio_slogf(0,  "sdio_set_blksz : Failed in CMD52 writing the second byte of block size to set block size for function %d", func);
		return (SDIO_FAILURE);
	}

	if (sdio_read_ioreg(sdio, 0, SDIO_FN_BLOCK_SIZE_1_REG(func), &reg) != SDIO_SUCCESS)
	{
		sdio_slogf(0,"warning: sdio_set_blksz: failed at calling sdio_read_ioreg, with reg=0x%x, func=%d\n\r",reg);
		sdio_slogf(0,  "sdio_set_blksz : Failed in CMD52 back reading the second byte of block size been set for function %d", func);
		return (SDIO_FAILURE);
	}
	if (reg != (blksz >> 8))
	{
		sdio_slogf(0,"warning: sdio_set_blksz: failed with (blksz>>8)=%d, reg=0x%x\n\r",(blksz>>8),reg);
		sdio_slogf(0,  "sdio_set_blksz : Back read value %d of the first byte of block size is different from written value %d", reg, blksz & 0xFF);
		return (SDIO_FAILURE);
	}

	sdio->blksz[func] = blksz;

	return SDIO_SUCCESS;
}
/*
 */
int sdio_enable_func(void *hdl, sdio_dev_t *dev, uint16_t blksz)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	uint8_t		i;

	if (dev->vid != 0xFFFF && dev->vid != sdio->dev_vid) {
		return (SDIO_FAILURE);
	}

	if (dev->did != 0xFFFF && dev->did != sdio->dev_did) {
		return (SDIO_FAILURE);
	}

	if (dev->fun == -1) {
		if (dev->ccd == 0xFF) {
			return (SDIO_FAILURE);
		}

		for (i = 0; i <= sdio->nfunc; i++) {
			if (sdio->func[i].ccd == dev->ccd) {
				dev->fun = i;
				break;
			}
		}
		if (i > sdio->nfunc) {
			return (SDIO_FAILURE);
		}
	} else {
		if (dev->fun > sdio->nfunc) {
			return (SDIO_FAILURE);
		}
		else {
			dev->ccd = sdio->func[dev->fun].ccd;
		}
	}

	if (sdio_set_blksz(hdl, dev->fun, blksz) != SDIO_SUCCESS) {
		return (SDIO_FAILURE);
	}
	
	if (sdio_func_intr(hdl, dev->fun,1) != SDIO_SUCCESS) {
		return (SDIO_FAILURE);
	}
	
	sdio->block_size(sdio->hchdl, blksz);

	return SDIO_SUCCESS;
}


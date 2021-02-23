/*
 * $QNXLicenseC:
 * Copyright 2014, QNX Software Systems. 
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

#include <proto.h>
#include <stdint.h>
#include "sdio.h"

#define IO_EN_TIMEOUT 500

/*
 * ---------------------------------------------------------------------------
 *  CardPendingInt
 *
 *      Determine whether sdio device is currently asserting the SDIO interrupt
 *      request.
 *	@sdio: the pointer to struct sdio_ext_t
 *	@func: the number of the function within the I/O card 
 *  Returns:
 *      1  - There is a pending interrupt
 *      0  - There is not a pending interrupt
 * ---------------------------------------------------------------------------
 */
int sdio_pending_int(sdio_ext_t *sdio, uint8_t func)
{
    unsigned char pending;
	pending=0;
	if (sdio_read_ioreg(sdio, 0, SDIO_INT_PENDING_REG, &pending) != SDIO_SUCCESS)
	{
		return SDIO_FAILURE;
	}
    return (pending & (1 << func)) ? 1 : 0;
} 
/*
 *	sdio_mask_int - mask interrupt a SDIO host controller
  *	@sdio: the pointer to struct sdio_ext_t
 *	@mask: 
 *			0 	mask interrupt a SDIO host controller
* 			1	clear mask interrupt a SDIO host controller
 */
#if 0
void sdio_mask_int(sdio_ext_t *sdio, int mask)
{
	sdio->ienable(sdio->hchdl, SDIO_INTR_SDIO, mask);
}
#endif

/*
 *	sdio_enable_int - enables interrupt a SDIO function for usage
  *	@sdio: the pointer to struct sdio_ext_t
 *	@func: the number of the function within the I/O card you wish to enable interrupt
 *	@enable: enable or disable the interrupt of sdio device 
 *	Returns 0 on success, -1  if failed
 */
int sdio_enable_int(sdio_ext_t *sdio, uint8_t func, int enable)
{
	
	if (func < 1 || func > 7)
		return (SDIO_FAILURE);
	
	sdio->ienable(sdio->hchdl, SDIO_INTR_SDIO, enable);
	
	if (enable)
	{
		sdio->wait_srv = 1;
		return sdio_set_ioreg(sdio, 0, SDIO_INT_ENABLE_REG, (1 << func)|(1<<0));
	}
	else
	{
		sdio->wait_srv = 0;
		return sdio_clr_ioreg(sdio, 0, SDIO_INT_ENABLE_REG, (1 << func)|(1<<0));
	}
	return (SDIO_SUCCESS);
}

/*
 *	sdio_enable_function - enables a SDIO function for usage
 *sdio: the pointer to struct sdio_ext_t
 *	@func: The number of the function within the I/O card you wish to enable 
 *	Returns 0 on success, -1  if failed
 */
int sdio_enable_function(sdio_ext_t *sdio, uint8_t func)
{
	uint8_t		io_en, io_rdy;
	int timeout;
	
	timeout=IO_EN_TIMEOUT;
	
	if (sdio_read_ioreg(sdio, 0, SDIO_IO_ENABLE_REG, &io_en) != SDIO_SUCCESS) {
		sdio_slogf(0, "sdio_enable_function : Failed in CMD52 reading register 0x%x of function %d", SDIO_IO_ENABLE_REG, func);
		return SDIO_FAILURE;
	}
	
	io_en |=(1<<func);

	if (sdio_write_ioreg(sdio, 0, SDIO_IO_ENABLE_REG, io_en) != SDIO_SUCCESS) {
		sdio_slogf(0, "sdio_enable_function : Failed in CMD52 writing register 0x%x of function %d", SDIO_IO_ENABLE_REG, func);
		return SDIO_FAILURE;
	}
	while(timeout>0)
	{

		if (sdio_read_ioreg(sdio, 0, SDIO_IO_READY_REG, &io_rdy) != SDIO_SUCCESS)
			return SDIO_FAILURE;

		if(io_rdy & (1<<func))
		{
			return (SDIO_SUCCESS);
		}
		delay(1);
		timeout--;
	}
	sdio_slogf(0, "sdio_enable_function : Function %d Could not able to be ready", func);
	return SDIO_FAILURE;
}



/**
 *	sdio_set_block_size - set the block size of a SDIO function
 *	@sdio: the pointer to struct sdio_ext_t
 *	@blksz: new block size or 0 to use the default.
 *	In the reading of 32, 64, 128, 256, and 512 bytes for the transfer of multiple blocks .
 *	Returns 0 on success, -1 if the host does not support the
 *	requested block size, or if one of the resultant FBR block
 *	size register writes failed.
 *
 */
int sdio_set_block_size(sdio_ext_t	*sdio, sdio_dev_t *dev, uint16_t blksz)
{

	uint8_t		i=0;
	
	if (dev->vid != 0xFFFF && dev->vid != sdio->dev_vid) {
		sdio_slogf(0,"warning: sdio_set_block_size: with dev->vid=0x%x, sdio->dev_vid=0x%x\n\r",dev->vid,sdio->dev_vid);
		//return (SDIO_FAILURE);
	}

	if (dev->did != 0xFFFF && dev->did != sdio->dev_did) {
		sdio_slogf(0,"warning: sdio_set_block_size: with dev->did=0x%x, sdio->dev_did=0x%x\n\r",dev->did,sdio->dev_did);
		//return (SDIO_FAILURE);
	}

	if (dev->fun == -1) {
		if (dev->ccd == 0xFF) {
			sdio_slogf(0,"warning: sdio_set_block_size: with dev->fun=0x%x, dev->ccd=0x%x\n\r",dev->fun,dev->ccd);
			//return (SDIO_FAILURE);
		}

		for (i = 0; i <= sdio->nfunc; i++) {
			if (sdio->func[i].ccd == dev->ccd) {
				dev->fun = i;
				break;
			}
		}
		if (i > sdio->nfunc) {
			sdio_slogf(0,"warning: sdio_set_block_size: i > sdio->nfunc with i=0x%x, sdio->nfunc=0x%x\n\r",i,sdio->nfunc);
			//return (SDIO_FAILURE);
		}
	} else {
		if (dev->fun > sdio->nfunc) {
			sdio_slogf(0,"warning: sdio_set_block_size: dev->fun>sdio->nfunc with dev->fun=0x%x, sdio->nfunc=0x%x\n\r",dev->fun,sdio->nfunc);
			//return (SDIO_FAILURE);
		}
		else {
			dev->ccd = sdio->func[dev->fun].ccd;
		}
	}
	for(i = 0; i < 20;i++)
	{
		if (sdio_set_blksz(sdio, dev->fun, blksz) == SDIO_SUCCESS) {
			break;	
		}
	}
	if(i >= 20)
	{
		sdio_slogf(0,"sdio_set_block_size: failed with dev->fun=0x%x, blksz=0x%x\n\r",dev->fun,blksz);
		return (SDIO_FAILURE);
	}
	
	sdio->block_size(sdio->hchdl, blksz);
	return SDIO_SUCCESS;
}





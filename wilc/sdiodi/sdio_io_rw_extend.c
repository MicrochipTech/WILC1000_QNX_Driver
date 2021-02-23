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

#include "sdio.h"
#if 0
/*
*	sdio_dma_iomem - transfer data with sdio device by using command 53. Host controller use DMA to transfer data
*	@hdl: pointer to struct sdio_ext_t
*	@write: if write=1 the function write data to sdio device, if write=0 the function read data from sdio device.
*	@func: the number of the function within the I/O card you wish to read or write.
*	@address: Start Address of I/O register to read or write
*	@opcode:  	opcode=0  Multi byte R/W to fixed address
*		        	opcode=1  Multi byte R/W to incrementing address
*
*   			opcode=0 is used to read or write multiple bytes of data to/from a single I/O register address. This command is useful when I/O data is transferred using a FIFO inside of
*			the I/O card. In this case, multiple bytes of data are transferred to/from a single register address.
*			opcode=1 is used to read or write multiple bytes of data to/from an I/O register address that increment by 1 after each operation. This command is used when large
*			amounts of I/O data exist within the I/O card in a RAM like data buffer. The first operation occurs at that address within the I/O card. The next operation shall occur
*			at address+1 with the address incrementing by 1 until the operation has completed
*	@blkcnt:  	the number of data blocks to be transferred
*	@blksz:  	the block size of the function
*	@paddr:  	the physical address contain data you wish to transfer with sdio device
*	Returns 0 on success, -1 if failed.
 *
 */
int
sdio_dma_iomem(sdio_ext_t	*sdio,uint8_t write, uint8_t func, uint32_t address,
				uint8_t opcode, uint32_t blkcnt, uint32_t blksz, off64_t paddr)
{

	int			nbytes = blkcnt * blksz;
	sdio_cmd_t	cmd;
	int timeout = 10000;
	if (sdio->blksz[func] != blksz)
	{
		if(sdio_set_block_size(sdio, &sdio->func[func], blksz) != SDIO_SUCCESS)
		{
			sdio_slogf(0,"sdio_dma_iomem failed with blkcnt=%d,blksz=%d at calling sdio_set_block_size\n\r",blkcnt,blksz);
			sdio_slogf(0, "sdio_dma_iomem : Could not set block size of %d to SDIO device", blksz);
			return (SDIO_FAILURE);
		}
	}
	if(blksz == 0)
		blksz = 512;
	cmd.opcode   = 53;
	cmd.rsptype  = SDIO_RSP_R5;
	cmd.eflags   = SDMMC_CMD_DATA;
	cmd.argument = write ? MAKE_SDIO_DIR(1): MAKE_SDIO_DIR(0);
	if((blkcnt==1)||(blkcnt==0))
		cmd.argument |=blksz;
	else
		cmd.argument |= MAKE_SDIO_BLOCK_MODE(1)|(blkcnt & 0x1ff );

	cmd.argument |= MAKE_SDIO_OFFSET(address) |
				    MAKE_SDIO_OP_CODE(opcode) |
				    MAKE_SDIO_FUNCTION(func) ;

	if (sdio->eflags & SDMMC_CAP_DMA)
	{
		if(write==0)
		{
			if (sdio->setup_dma(sdio->hchdl, paddr, nbytes, MMC_DIR_IN) != nbytes)
			{
				sdio_slogf(0,"sdio_dma_iomem failed with write=%d, at calling sdio->setup_dma.\n\r",write);
				sdio_slogf(0, "sdio_dma_iomem : Failed in setting up DMA read transfer with size = %d", nbytes);
				return (SDIO_FAILURE);
			}
		}
		else
		{
			if (sdio->setup_dma(sdio->hchdl, paddr, nbytes, MMC_DIR_OUT) != nbytes)
			{
				sdio_slogf(0,"sdio_dma_iomem failed with write=%d, at calling sdio->setup_dma.\n\r",write);
				sdio_slogf(0, "sdio_dma_iomem : Failed in setting up DMA write transfer with size = %d", nbytes);
				return (SDIO_FAILURE);
			}
		}
		sdio->wait_data = 1;
		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
		{
			sdio_slogf(0,"sdio_dma_iomem failed with write=%d, at calling sdio_send_command.\n\r",write);
			sdio_slogf(0, "sdio_dma_iomem : Failed in sending CMD53 to %s %d bytes at address 0x%x", write==1?"write":"read", nbytes, address);
			return (SDIO_FAILURE);
		}
		if(sdio->istatus & SDMMC_INT_ERROR)
		{
			sdio_slogf(0,"sdio_dma_iomem failed with write =%d sdio->istatus=0x%x\n\r",write,sdio->istatus);
			sdio_slogf(0, "sdio_dma_iomem : Error while sending CMD53 to SDIO device with error %x", sdio->istatus);
			return (SDIO_FAILURE);
		}
		while(timeout--)
		{
			pthread_sleepon_lock();
			if(sdio->istatus & SDMMC_INT_ERROR)
			{
				sdio_slogf(0,"sdio_dma_iomem failed with write =%d sdio->istatus=0x%x\n\r",write,sdio->istatus);
				sdio_slogf(0, "sdio_dma_iomem : Error while sending CMD53 to SDIO device with error %x", sdio->istatus);
				return (SDIO_FAILURE);
			}
			if(sdio->istatus & SDMMC_INT_DATA)
			{
				break;
			}
			if (sdio->wait_data >= 1)
			{
				if (pthread_sleepon_timedwait(&sdio->wait_data, 1000 * 1000 * 1000) != EOK)
				{

					nanospin_ns(1000);
				}
				if(timeout <= 0)
				{
					sdio_slogf(0,"sdio_dma_iomem timeout with write =%d \n\r");
					sdio_slogf(0, "sdio_dma_iomem : Data time-out in waiting DMA transfer complete");
					return (SDIO_FAILURE);
				}
				nanospin_ns(1000000);
			}
			pthread_sleepon_unlock();
		}
		sdio->wait_data = 0;

		if(write == 0)
		{
			if (sdio->dma_done(sdio->hchdl, MMC_DIR_IN) != MMC_SUCCESS)
			{
				sdio_slogf(0,"sdio_dma_iomem failed with write =%d, at calling sdio->dma_done.\n\r",write);
				sdio_slogf(0, "sdio_dma_iomem : DMA read transfer completed with error");
				return (SDIO_FAILURE);
			}
		}
		else
		{
			if (sdio->dma_done(sdio->hchdl, MMC_DIR_OUT) != MMC_SUCCESS)
			{
				sdio_slogf(0,"sdio_dma_iomem failed with write =%d, at calling sdio->dma_done.\n\r",write);
				sdio_slogf(0, "sdio_dma_iomem : DMA write transfer completed with error");
				return (SDIO_FAILURE);
			}
		}

	}
	else
	{
		sdio_slogf(0,"sdio_dma_iomem failed with write =%d, sdio->eflags\n\r",write,sdio->eflags);
		sdio_slogf(0, "sdio_dma_iomem: Not set 'SDMMC_CAP_DMA' to 'eflags' to read/write by DMA");
		return (SDIO_FAILURE);
	}
	return (SDIO_SUCCESS);
}
/*
*	sdio_pio_iomem - transfer data with sdio device by using command 53. Host controller does not use DMA to transfer data
*	@hdl: pointer to struct sdio_ext_t
*	@write: if write=1 the function write data to sdio device, if write=0 the function read data from sdio device.
*	@func: the number of the function within the I/O card you wish to read or write.
*	@address: Start Address of I/O register to read or write
*	@opcode:  	opcode=0  Multi byte R/W to fixed address
*		        opcode=1  Multi byte R/W to incrementing address
*
*   			opcode=0 is used to read or write multiple bytes of data to/from a single I/O register address. This command is useful when I/O data is transferred using a FIFO inside of
*			the I/O card. In this case, multiple bytes of data are transferred to/from a single register address.
*			opcode=1 is used to read or write multiple bytes of data to/from an I/O register address that increment by 1 after each operation. This command is used when large
*			amounts of I/O data exist within the I/O card in a RAM like data buffer. The first operation occurs at that address within the I/O card. The next operation shall occur
*			at address+1 with the address incrementing by 1 until the operation has completed
*	@blkcnt:  	the number of data blocks to be transferred
*	@blksz:  	the block size of the function
*	@buffer:  	the buffer address contain data you wish to transfer with sdio device
*	Returns 0 on success, -1 if failed.
 *
 */
int
sdio_pio_iomem(sdio_ext_t	*sdio, uint8_t write, uint8_t func, uint32_t address,
				uint8_t opcode, uint32_t blkcnt, uint32_t blksz, uint8_t *buffer)
{

	int			nbytes = blkcnt * blksz;
	sdio_cmd_t	cmd;
	int i;

	if (sdio->blksz[func] != blksz)
	{
		if(sdio_set_block_size(sdio, &sdio->func[func], blksz) != SDIO_SUCCESS)
		{
			sdio_slogf(0,"sdio_pio_iomem failed with blkcnt=%d,blksz=%d at calling sdio_set_block_size\n\r",blkcnt,blksz);
			sdio_slogf(0, "sdio_pio_iomem : Could not set block size of %d to SDIO device", blksz);
			return (SDIO_FAILURE);
		}
	}

	if(blksz==0)
		blksz=512;

	cmd.opcode   = 53;
	cmd.rsptype  = SDIO_RSP_R5;
	cmd.eflags   = SDMMC_CMD_DATA;
	cmd.argument = write ? MAKE_SDIO_DIR(1): MAKE_SDIO_DIR(0);
	if((blkcnt==1)||(blkcnt==0))
		cmd.argument |= blksz;
	else
		cmd.argument |= MAKE_SDIO_BLOCK_MODE(1)|(blkcnt & 0x1ff );

	cmd.argument |= MAKE_SDIO_OFFSET(address) |
				    MAKE_SDIO_OP_CODE(opcode) |
				    MAKE_SDIO_FUNCTION(func) ;

	if (sdio->eflags & SDMMC_CAP_PIO)
	{
		if (sdio->setup_pio(sdio->hchdl, nbytes, MMC_DIR_IN) != nbytes)
		{
			sdio_slogf(0,"sdio_pio_iomem failed with write=%d, at calling sdio->setup_pio.\n\r",write);
			sdio_slogf(0, "sdio_pio_iomem : Failed in setting up PIO transfer with size = %d", nbytes);
			return (SDIO_FAILURE);
		}
		if(write)
			sdio->wait_bwe = 1;
		else
			sdio->wait_bre = 1;

		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
		{
			sdio_slogf(0,"sdio_pio_iomem failed with write=%d, at calling sdio_send_command.\n\r",write);
			sdio_slogf(0, "sdio_pio_iomem : Failed in sending CMD53 to %s %d bytes at address 0x%x", write==1?"write":"read", nbytes, address);
			return (SDIO_FAILURE);
		}

		for(i = 0; i < blkcnt; i++)
		{
			if(write)
			{
				while(1)
				{
					pthread_sleepon_lock();
					if (sdio->wait_bwe == 1)
					{
						if (pthread_sleepon_timedwait(&sdio->wait_bwe, 1000 * 1000 * 1000) != EOK)
						{
							;
						}
					}
					pthread_sleepon_unlock();
					if (sdio->wait_bwe > 1)
					{
						sdio->pio_done(sdio->hchdl, (char *)(buffer+i*blksz), blksz, MMC_DIR_OUT );
						break;
					}
					else
					{
						sdio_slogf(0,"sdio_pio_iomem falied with write =%d, sdio->wait_bwe=0x%x\n\r",write,sdio->wait_bwe);
						sdio_slogf(0, "sdio_pio_iomem : Failed in waiting for SDIO device receiving data (data time-out)");
						return (SDIO_FAILURE);
					}
					sdio->wait_bwe = 1;
					if(sdio->istatus & SDMMC_INT_ERROR)
					{
						sdio_slogf(0,"sdio_pio_iomem failed with write =%d sdio->istatus=0x%x\n\r",write,sdio->istatus);
						sdio_slogf(0, "sdio_pio_iomem : Error while writing data to SDIO device with error %x", sdio->istatus);
						return (SDIO_FAILURE);
					}
				}
			}
			else
			{
				while(1)
				{
					pthread_sleepon_lock();
					if (sdio->wait_bre == 1)
					{
						if (pthread_sleepon_timedwait(&sdio->wait_bre, 1000 * 1000 * 1000) != EOK)
						{
							;
						}
					}
					pthread_sleepon_unlock();
					if (sdio->wait_bre > 1)
					{
						sdio->pio_done(sdio->hchdl, (char *)(buffer+i*blksz), blksz, MMC_DIR_IN );
						break;
					}

					sdio->wait_bre = 1;

					if(sdio->istatus & SDMMC_INT_ERROR)
					{
						sdio_slogf(0,"sdio_pio_iomem failed with write =%d, at calling sdio->pio_done.\n\r",write);
						sdio_slogf(0, "sdio_pio_iomem : Error while reading data from SDIO device with error %x", sdio->istatus);
						return (SDIO_FAILURE);
					}
				}
			}
		}
	}
	else
	{
		sdio_slogf(0,"sdio_pio_iomem failed with write =%d, sdio->eflags\n\r",write,sdio->eflags);
		sdio_slogf(0, "sdio_pio_iomem: Not set 'SDMMC_CAP_PIO' to 'eflags' to read/write by PIO");
		return (SDIO_FAILURE);
	}
	return (SDIO_SUCCESS);
}
#endif
int
sdio_read_iomem(void *hdl, uint8_t fn, uint32_t address, 
				uint8_t opcode, uint32_t blkcnt, uint32_t blksz, uint8_t *buffer, off64_t paddr)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	int			nbytes = blkcnt * blksz;
	int rdbytes = 0;
	sdio_cmd_t	cmd;
	int ret = 0;
	printf("%s get blksz %d, function[%d] blksz %d.\n",__FUNCTION__,blksz,fn,sdio->blksz[fn]);
	if (sdio->blksz[fn] != blksz) {
		if (sdio_set_blksz(hdl, fn, blksz) != SDIO_SUCCESS)
			return (SDIO_FAILURE);
	}

	cmd.opcode   = 53;
	cmd.rsptype  = SDIO_RSP_R5;
	cmd.eflags   = SDMMC_CMD_DATA_IN | SDMMC_CMD_DATA | (blkcnt > 1 ? SDMMC_CMD_DATA_MULTI : 0);
	cmd.argument = MAKE_SDIO_OFFSET(address) |
				    MAKE_SDIO_OP_CODE(opcode) |
				    MAKE_SDIO_BLOCK_MODE(1) |
				    MAKE_SDIO_FUNCTION(fn) |
				    MAKE_SDIO_DIR(0) | (blkcnt & 0x01FF);
	cmd.blkcnt   = blkcnt;			// block count;
	cmd.size     = blksz;			// block size 
	if (sdio->eflags & SDMMC_CAP_DMA) {
		CACHE_INVAL(&sdio->cachectl, buffer, paddr, nbytes);

		if (sdio->setup_dma(sdio->hchdl, paddr, nbytes, MMC_DIR_IN) != nbytes)
			return (SDIO_FAILURE);

		cmd.eflags |= SDMMC_CMD_DATA_DMA;
		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
			return (SDIO_FAILURE);

		if (sdio->dma_done(sdio->hchdl, MMC_DIR_IN) != MMC_SUCCESS)
			return (SDIO_FAILURE);
	} else {

		if ((ret = sdio->setup_pio(sdio->hchdl, (char *)buffer, nbytes, MMC_DIR_IN) )!= nbytes){
			printf("%s error: return %d.\n","sdio->setup_pio",ret);
			return (SDIO_FAILURE);
		}
		cmd.data = buffer;			// buffer pointer

		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS){
			printf("%s error: return %d.\n","sdio_send_command",ret);
			return (SDIO_FAILURE);
		}
		if ((rdbytes = sdio->pio_done(sdio->hchdl, (char *)buffer, nbytes, MMC_DIR_IN) )!= nbytes){
			printf("Warning: get %d bytes.\n",rdbytes);
			return (SDIO_FAILURE);
		}

	}

	return (SDIO_SUCCESS);
}

int
sdio_write_iomem(void *hdl, uint8_t fn, uint32_t address, 
				uint8_t opcode, uint32_t blkcnt, uint32_t blksz, uint8_t *buffer, off64_t paddr)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	int			nbytes = blkcnt * blksz;
	sdio_cmd_t	cmd;

	if (sdio->blksz[fn] != blksz) {
		if (sdio_set_blksz(hdl, fn, blksz) != SDIO_SUCCESS)
			return (SDIO_FAILURE);
	}

	cmd.opcode   = 53;
	cmd.rsptype  = SDIO_RSP_R5;
	cmd.eflags   = SDMMC_CMD_DATA | (blkcnt > 1 ? SDMMC_CMD_DATA_MULTI : 0);
	cmd.argument = MAKE_SDIO_OFFSET(address) |
				    MAKE_SDIO_OP_CODE(opcode) |
				    MAKE_SDIO_BLOCK_MODE(1) |
				    MAKE_SDIO_FUNCTION(fn) |
				    MAKE_SDIO_DIR(1) | (blkcnt & 0x01FF);
	cmd.blkcnt   = blkcnt;			// block count;
	cmd.size     = blksz;			// block size 

	if (sdio->eflags & SDMMC_CAP_DMA) {
		CACHE_FLUSH(&sdio->cachectl, buffer, paddr, blksz * blkcnt);

		if (sdio->setup_dma(sdio->hchdl, paddr, nbytes, MMC_DIR_OUT) != nbytes)
			return (SDIO_FAILURE);

		cmd.eflags |= SDMMC_CMD_DATA_DMA;
		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
			return (SDIO_FAILURE);

		if (sdio->dma_done(sdio->hchdl, 0) != MMC_SUCCESS)
			return (SDIO_FAILURE);
	} else {
		if (sdio->setup_pio(sdio->hchdl, (char *)buffer, nbytes, MMC_DIR_OUT) != nbytes)
			return (SDIO_FAILURE);

		cmd.data = buffer;			// buffer pointer

		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
			return (SDIO_FAILURE);

		if (sdio->pio_done(sdio->hchdl, (char *)buffer, nbytes, MMC_DIR_OUT) != nbytes)
			return (SDIO_FAILURE);
	}

	return (SDIO_SUCCESS);
}


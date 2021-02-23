/*
 * $QNXLicenseC:
 * Copyright 2007, 2008, QNX Software Systems. 
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


#include <arm/inout.h>
#include <sim_bs.h>
#include <string.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#define MMCSD_VENDOR_TI_OMAP3

#ifdef MMCSD_VENDOR_TI_OMAP3

#include	<sim_omap3.h>
#include	<sys/syspage.h>
#include	<hw/sysinfo.h>
#include	"proto.h"
#define SDIO_TRACE_DEBUG
#if defined(SDIO_TRACE_DEBUG)
#define TRACE  slogf(99,1, "TRACE [%s]", __FUNCTION__)
#define TRACE_ENTER slogf(99,1, "%s enter", __FUNCTION__)
#define TRACE_EXIT slogf(99,1, "%s exit", __FUNCTION__)
#define DEBUG_MSG(x) slogf(99,1, "%s %s", __FUNCTION__, x)
#define DEBUG_CMD(x)  x
#else
#define TRACE
#define TRACE_ENTER
#define TRACE_EXIT
#define DEBUG_MSG(x)
#define DEBUG_CMD(x)
#endif
static void omap_set_bus_mode(void* hchdl,int mode);

static int omap3_ienable(void *hdl, int irq, int enable)
{
	omap3_ext_t		*ctx = (omap3_ext_t *)hdl;
	uintptr_t		base  = ctx->mmc_base;

/* Note: This can be called from an interrupt isr */

	if (enable) {
		//DEBUG_CMD(slogf(99,1,"[omap3_ienable] enable\n");)
		out32(base + OMAP3_MMCHS_IE,in32(base + OMAP3_MMCHS_IE) & ~INTR_CIRQ);
		out32(base + OMAP3_MMCHS_ISE,in32(base + OMAP3_MMCHS_ISE) | INTR_CIRQ);
		out32(base + OMAP3_MMCHS_IE, in32(base + OMAP3_MMCHS_IE)  | INTR_CIRQ);
		//slogf(_SLOGC_SIM_MMC, _SLOG_ERROR, "%s ise %x ie %x stat %x",  __FUNCTION__,
		//in32(base + OMAP3_MMCHS_ISE), in32(base + OMAP3_MMCHS_IE), in32(base + OMAP3_MMCHS_STAT));
	 } else {
		 //DEBUG_CMD(slogf(99,1,"[omap3_ienable] disable\n");)
		 out32(base + OMAP3_MMCHS_ISE,in32(base + OMAP3_MMCHS_ISE) & ~INTR_CIRQ);
	 }

	return (MMC_SUCCESS);
}



/*
 * Interrupt validate
 */
static int omap3_ivalidate(void *hdl, int irq, int busy)
{
	omap3_ext_t  *ctx = (omap3_ext_t *)hdl;
	uintptr_t		base  = ctx->mmc_base;
	uint32_t		sts;
	int ret = SDIO_INTR_SDIO;


	sts = in32(base + OMAP3_MMCHS_STAT);
	//slogf(99,1,"%s sts %x.", __FUNCTION__, sts);

	// not interrupt
	if (!sts)
		return (SDIO_INTR_NONE);


	sts &= in32(base + OMAP3_MMCHS_ISE) | INTR_ERRI ;
 	/*
    * Check card interrupt
    */
	if (sts & INTR_CIRQ) {
		out32(base + OMAP3_MMCHS_ISE, ~(INTR_CIRQ | INTR_ERRI));
		out32(base + OMAP3_MMCHS_IE, ~(INTR_CIRQ | INTR_ERRI));

      ctx->mask = 0;
      if (!busy)
         return (SDIO_INTR_CARD);

      /*
       * Client can't accept event now, so we set the event flag,
       * return a fake SDIO interrupt, SDIO thread will queue the event
       */
      atomic_set(&ctx->sts, INTR_CIRQ);
      return (SDIO_INTR_SDIO);
   }

	out32(base + OMAP3_MMCHS_STAT, sts  & ~(INTR_CIRQ | INTR_ERRI));

	ctx->sts = sts;

	return (ret);
}


/*
 * Interrupt process,
 */
static int omap3_iprocess(void *hdl, sdio_cmd_t *cmd)
{
	omap3_ext_t   *ctx = (omap3_ext_t *)hdl;
	uintptr_t		base  = ctx->mmc_base;
	uint32_t       ests, nsts;
	int				intr = 0;

	ests = ctx->sts & OMAP3_MMCHS_ERRORS_FLAGS;
	nsts = ests ^ ctx->sts;

	// Check SDIO interrupt
	if (nsts & INTR_CIRQ) {
		atomic_clr(&ctx->sts, INTR_CIRQ);
		intr |= SDMMC_INT_SERVICE;
		nsts &= ~INTR_CIRQ;
   }

	if (ests) {
		if (ests & INTR_DTO) {
			intr |= SDMMC_INT_ERRDT;
			out32(base + OMAP3_MMCHS_SYSCTL, in32(base + OMAP3_MMCHS_SYSCTL) | SYSCTL_SRD);
			while (in32(base + OMAP3_MMCHS_SYSCTL) & SYSCTL_SRD)
				;
		}
		if (ests & INTR_DCRC) {
			intr |= SDMMC_INT_ERRDC;
		}
		if (ests & INTR_DEB) {
			intr |= SDMMC_INT_ERRDE;
		}

		if (ests & INTR_CTO) {
			intr |= SDMMC_INT_ERRCT;
			out32(base + OMAP3_MMCHS_SYSCTL, in32(base + OMAP3_MMCHS_SYSCTL) | SYSCTL_SRC);
			while (in32(base + OMAP3_MMCHS_SYSCTL) & SYSCTL_SRC);
		}
		if (ests & INTR_CCRC) {
			intr |= SDMMC_INT_ERRCC;
		}
		if (ests & INTR_CEB) {
			intr |= SDMMC_INT_ERRCE;
		}
		if (ests & INTR_CIE) {
			intr |= SDMMC_INT_ERRCI;
		}
		atomic_clr(&ctx->sts, ests);
	}
	else {
		if (nsts & INTR_CC) {
			intr |= SDMMC_INT_COMMAND;
			atomic_clr(&ctx->sts, INTR_CC);
			if (cmd) {
				if (cmd->rsptype & MMC_RSP_136) {
					cmd->resp[3] = in32(base + OMAP3_MMCHS_RSP76);
					cmd->resp[2] = in32(base + OMAP3_MMCHS_RSP54);
					cmd->resp[1] = in32(base + OMAP3_MMCHS_RSP32);
					cmd->resp[0] = in32(base + OMAP3_MMCHS_RSP10);
				} else if (cmd->rsptype & MMC_RSP_PRESENT) {
					cmd->resp[0] = in32(base + OMAP3_MMCHS_RSP10);
				}
			}


			if (cmd->rsptype & MMC_RSP_BUSY) {
				int		i;

				for (i = 1024 * 256; i > 0; i--) {
					if (in32(base + OMAP3_MMCHS_PSTATE) & PSTATE_DLA) {
						nanospin_ns(1024);
						continue;
					}
					break;
				}
				if (i <= 0) {
					intr |= SDMMC_INT_ERROR;
				}

			}
		}

		if (nsts & (INTR_TC | INTR_BWR | INTR_BRR)) {
			if (nsts & INTR_TC) {
				intr |= SDMMC_INT_DATA;
			}
			if (nsts & INTR_BRR) {
				intr |= SDMMC_INT_RBRDY;
			}
			if (nsts & INTR_BWR) {
				intr |= SDMMC_INT_WBRDY;
			}

		}
	}

	if (intr)
		out32(base + OMAP3_MMCHS_IE,  (in32(base + OMAP3_MMCHS_IE) & INTR_CIRQ) );

	return intr;
}
static int omap3_setup_pio(void *ext_hdl, char *buf,int len, int dir)
{

	omap3_ext_t		*omap3 = (omap3_ext_t *)ext_hdl;
	int				nblk;

	nblk = len / omap3->blksz;
	len  = nblk * omap3->blksz;

	omap3->dcmd = CMD_DP;
	if (nblk > 1) {
		omap3->dcmd |= CMD_MBS | CMD_BCE;
	}
	if (dir == MMC_DIR_IN) {
		omap3->dcmd |= CMD_DDIR;
		omap3->dmask = INTR_BRR;
	} else
		omap3->dmask = INTR_BWR;

	out32(omap3->mmc_base + OMAP3_MMCHS_BLK, (nblk << 16) | omap3->blksz);

	return (len);
}

static int omap3_pio_done(void *ext_hdl, char *buf, int len, int dir)
{
	uintptr_t		base;
	int				nbytes, cnt;
	uint32_t		*pbuf = (uint32_t *)buf;
	int 			byte_sent = 0;
	int 			byte_read = 0;

	omap3_ext_t		*omap3 = (omap3_ext_t *)ext_hdl;

	base  = omap3->mmc_base;

	cnt = nbytes = len < MMCHS_FIFO_SIZE ? len : MMCHS_FIFO_SIZE;

	if (dir == MMC_DIR_IN) {

		if (!(in32(base + OMAP3_MMCHS_PSTATE) & PSTATE_BRE)) {
			out32(base + OMAP3_MMCHS_IE, INTR_BRR);
			return 0;
		}

		while (byte_read < len)
		{

			{
				for (; nbytes > 0; nbytes -= 4)
				{
					while (!(in32(base + OMAP3_MMCHS_PSTATE) & PSTATE_BRE));
					*pbuf++ = in32(base + OMAP3_MMCHS_DATA);
				}
				byte_read += cnt;
				nbytes = cnt;
			}
		}
		return byte_read;
	} else {


		while (byte_sent < len)
		{
			for (; nbytes > 0; nbytes -= 4)
			{
				while (!(in32(base + OMAP3_MMCHS_PSTATE) & PSTATE_BWE));
				out32(base + OMAP3_MMCHS_DATA, *pbuf++);
			}
			byte_sent += cnt;
			nbytes = cnt;

			if (len == byte_sent)
				out32(base + OMAP3_MMCHS_IE, INTR_TC);


		}
	}

	return byte_sent;
}

#ifdef USE_EDMA
static void omap3_edma_bit(omap3_ext_t	*omap3, int reg, int channel)
{
	uintptr_t   base = omap3->dma_base + DRA446_SHADOW0_OFF + reg;

	if (channel > 31) {
		base    += 4;
		channel -= 32;
	}

	out32(base, 1 << channel);
}

static void omap3_edma_done(omap3_ext_t	*omap3, int channel)
{
	uintptr_t	base = omap3->dma_base + DRA446_SHADOW0_OFF;

	dra446_param	*param = (dra446_param *)(omap3->dma_base + DRA446_PARAM(channel));

	if (channel > 31) {
		base    += 4;
		channel -= 32;
	}

	if (in32(base + DRA446_EDMA_ER) & in32(base + DRA446_EDMA_EER)) {
		int i=100;
		while (param->ccnt != 0 && i--){
			printf("%s(%d): %d %x \n", __func__, __LINE__, channel, param->ccnt);
			delay(1);
		}
	}

	/* Disable this EDMA event */
	omap3_edma_bit(omap3, DRA446_EDMA_EECR, channel);
}


static void omap3_setup_rx_edma(omap3_ext_t *omap3, paddr_t addr, int len)
{
	dra446_param	*param;
	int				chnl = omap3->dma_rreq;

	/*
	 * In case there is a pending event
	 */
	omap3_edma_bit(omap3, DRA446_EDMA_ECR, chnl);

	/*
	 * Initialize Rx DMA channel
	 */
	param = (dra446_param *)(omap3->dma_base + DRA446_PARAM(chnl));
	param->opt =  (0 << 23)		/* ITCCHEN = 0 */
				| (0 << 22)		/* TCCHEN = 0 */
				| (0 << 21)		/* */
				| (0 << 20)		/* */
				| (chnl << 12)		/* TCC */
				| (0 << 11)		/* Normal completion */
				| (0 << 3)		/* PaRAM set is not static */
				| (1 << 2)		/* AB-synchronizad */
				| (0 << 1)		/* Destination address increment mode */
				| (0 << 0);		/* Source address increment mode */

	param->src          = omap3->mmc_pbase + OMAP3_MMCHS_DATA;
	param->abcnt        = (128 << 16) | 4;
	param->dst          = addr;
	param->srcdstbidx   = (4 << 16) | 0;
	param->linkbcntrld  = 0xFFFF;
	param->srcdstcidx   = (512<< 16) | 0;
	param->ccnt         = len / 512;

	/*
	 * Enable event
	 */
	omap3_edma_bit(omap3, DRA446_EDMA_EESR, chnl);
}

static void omap3_setup_tx_edma(omap3_ext_t *omap3, paddr_t addr, int len)
{
	dra446_param	*param;
	int				chnl = omap3->dma_treq;

	/*
	 * In case there is a pending event
	 */
	omap3_edma_bit(omap3, DRA446_EDMA_ECR, chnl);

	/*
	 * Initialize Tx DMA channel
	 */
	param = (dra446_param *)(omap3->dma_base + DRA446_PARAM(chnl));
	param->opt =  (0<< 23)		/* ITCCHEN = 0 */
				| (0 << 22)		/* TCCHEN = 0 */
				| (0 << 21)		/* */
				| (0 << 20)		/* */
				| (chnl << 12)	/* TCC */
				| (0 << 11)		/* Normal completion */
				| (0 << 3)		/* PaRAM set is not static */
				| (1 << 2)		/* AB-synchronizad */
				| (0 << 1)		/* Destination address increment mode */
				| (0 << 0);		/* Source address increment mode */

	param->src          = addr;
	param->abcnt        = (128 << 16) | 4;
	param->dst          = omap3->mmc_pbase + OMAP3_MMCHS_DATA;
	param->srcdstbidx   = (0 << 16) | 4;
	param->linkbcntrld  = 0xFFFF;
	param->srcdstcidx   = (0 << 16) | 512;
	param->ccnt         = len / 512;

	/*
	 * Enable event
	 */
	omap3_edma_bit(omap3, DRA446_EDMA_EESR, chnl);
}

static int omap3_setup_dma(void *ext_hdl, paddr_t paddr, int len, int dir)
{
	sdio_ext_t * ext = (sdio_ext_t *)ext_hdl;
	omap3_ext_t		*omap = (omap3_ext_t *)ext->hchdl;

	len = ext->setup_pio(ext,NULL, len, dir);
	
	if(len>0){
		if (dir == MMC_DIR_IN) {	// read
			/* setup receive EDMA channel */
			omap3_setup_rx_edma(omap, paddr, len);
		} else {
			/* setup transmit EDMA channel */
			omap3_setup_tx_edma(omap, paddr, len);
		}
		omap->dcmd |= CMD_DE;
		omap->dmask = INTR_TC; 	// Use transfer complete interrupt
		omap->dsize = len;
	}
	return (len);
}

static int omap3_dma_done(void *hdl, int dir)
{
	omap3_ext_t		*omap;

	omap = (omap3_ext_t *)hdl;

	if (dir == MMC_DIR_IN)
		omap3_edma_done(omap, omap->dma_rreq);
	else
		omap3_edma_done(omap, omap->dma_treq);

	return MMC_SUCCESS;
}

#else
static int omap3_setup_dma(void *ext, paddr_t paddr, int len, int dir)
{
	omap3_ext_t		*omap3;
	dma4_param		*param;

	omap3 = (omap3_ext_t *)ext;

	//
	// Initialize Tx DMA channel
	//
	param = (dma4_param *)(omap3->dma_base + DMA4_CCR(omap3->dma_chnl));

	len = omap3_setup_pio(hba, len, dir);

	if (len > 0) {
		// Clear all status bits
		param->csr  = 0x1FFE;
		param->cen  = len >> 2;
		param->cfn  = 1;			// Number of frames
		param->cse  = 1;
		param->cde  = 1;
		param->cicr = 0;			// We don't want any interrupts

		if (dir == MMC_DIR_IN) {
			// setup receive SDMA channel
			param->csdp = (2 <<  0)		// DATA_TYPE = 0x2:  32 bit element
						| (0 <<  2)		// RD_ADD_TRSLT = 0: Not used
						| (0 <<  6)		// SRC_PACKED = 0x0: Cannot pack source data
						| (0 <<  7)		// SRC_BURST_EN = 0x0: Cannot burst source
						| (0 <<  9)		// WR_ADD_TRSLT = 0: Undefined
						| (0 << 13)		// DST_PACKED = 0x0: No packing
						| (3 << 14)		// DST_BURST_EN = 0x3: Burst at 16x32 bits
						| (1 << 16)		// WRITE_MODE = 0x1: Write posted
						| (0 << 18)		// DST_ENDIAN_LOCK = 0x0: Endianness adapt
						| (0 << 19)		// DST_ENDIAN = 0x0: Little Endian type at destination
						| (0 << 20)		// SRC_ENDIAN_LOCK = 0x0: Endianness adapt
						| (0 << 21);	// SRC_ENDIAN = 0x0: Little endian type at source

			param->ccr  = DMA4_CCR_SYNCHRO_CONTROL(omap3->dma_rreq)	// Synchro control bits
						| (1 <<  5)		// FS = 1: Packet mode with BS = 0x1
						| (0 <<  6)		// READ_PRIORITY = 0x0: Low priority on read side
						| (0 <<  7)		// ENABLE = 0x0: The logical channel is disabled.
						| (0 <<  8)		// DMA4_CCRi[8] SUSPEND_SENSITIVE = 0
						| (0 << 12)		// DMA4_CCRi[13:12] SRC_AMODE = 0x0: Constant address mode
						| (1 << 14)		// DMA4_CCRi[15:14] DST_AMODE = 0x1: Post-incremented address mode
						| (1 << 18)		// DMA4_CCRi[18] BS = 0x1: Packet mode with FS = 0x1
						| (1 << 24)		// DMA4_CCRi[24] SEL_SRC_DST_SYNC = 0x1: Transfer is triggered by the source. The packet element number is specified in the DMA4_CSFI register.
						| (0 << 25);	// DMA4_CCRi[25] BUFFERING_DISABLE = 0x0

			param->cssa = omap3->mmc_pbase + OMAP3_MMCHS_DATA;
			param->cdsa = paddr;
			param->csf  = omap3->blksz >> 2;
		} else {
			// setup transmit SDMA channel
			param->csdp = (2 <<  0)		// DATA_TYPE = 0x2:  32 bit element
						| (0 <<  2)		// RD_ADD_TRSLT = 0: Not used
						| (0 <<  6)		// SRC_PACKED = 0x0: Cannot pack source data
						| (3 <<  7)		// SRC_BURST_EN = 0x3: Burst at 16x32 bits
						| (0 <<  9)		// WR_ADD_TRSLT = 0: Undefined
						| (0 << 13)		// DST_PACKED = 0x0: No packing
						| (0 << 14)		// DST_BURST_EN = 0x0: Cannot Burst
						| (0 << 16)		// WRITE_MODE = 0x0: Write not posted
						| (0 << 18)		// DST_ENDIAN_LOCK = 0x0: Endianness adapt
						| (0 << 19)		// DST_ENDIAN = 0x0: Little Endian type at destination
						| (0 << 20)		// SRC_ENDIAN_LOCK = 0x0: Endianness adapt
						| (0 << 21);	// SRC_ENDIAN = 0x0: Little endian type at source

			param->ccr  = DMA4_CCR_SYNCHRO_CONTROL(omap3->dma_treq)
						| (1 <<  5)		// FS = 1: Packet mode with BS = 0x1
						| (0 <<  6)		// READ_PRIORITY = 0x0: Low priority on read side
						| (0 <<  7)		// ENABLE = 0x0: The logical channel is disabled.
						| (0 <<  8)		// DMA4_CCRi[8] SUSPEND_SENSITIVE = 0
						| (1 << 12)		// DMA4_CCRi[13:12] SRC_AMODE = 0x1: Post-incremented address mode
						| (0 << 14)		// DMA4_CCRi[15:14] DST_AMODE = 0x0: Constant address mode
						| (1 << 18)		// DMA4_CCRi[18] BS = 0x1: Packet mode with FS = 0x1
						| (0 << 24)		// DMA4_CCRi[24] SEL_SRC_DST_SYNC = 0x0: Transfer is triggered by the source. The packet element number is specified in the DMA4_CSFI register.
						| (0 << 25);	// DMA4_CCRi[25] BUFFERING_DISABLE = 0x0

			param->cssa = paddr;
			param->cdsa = omap3->mmc_pbase + OMAP3_MMCHS_DATA;
			param->cdf  = omap3->blksz >> 2;
		}

		// Enable DMA event
		param->ccr |= 1 << 7;

		omap3->dcmd |= CMD_DE;
		omap3->dmask = INTR_TC;		// Use transfer complete interrupt
		omap3->dsize = len;
	}

	return (len);
}

static int omap3_dma_done(void *ext, int dir)
{
	omap3_ext_t		*omap3;
	dma4_param		*param;
	int				ret = MMC_SUCCESS;

	omap3 = (omap3_ext_t *)ext;

	param = (dma4_param *)(omap3->dma_base + DMA4_CCR(omap3->dma_chnl));

#define	OMAP3_SDMA_ERROR	((1 << 11) | (1 << 10) | (1 << 9) | (1 << 8))
	while (1) {
		// transfer complete?
		if (param->ccen == (omap3->dsize >> 2))
			break;
		// Check DMA errors
		if (param->csr & OMAP3_SDMA_ERROR)
			break;
	}
	if (param->csr & OMAP3_SDMA_ERROR)
		ret = MMC_FAILURE;

	// Disable this DMA event
	param->ccr = 0;

	// Clear all status bits
	param->csr = 0x1FFE;

	return ret;
}
#endif

static int omap3_command_done(void *ext, sdio_cmd_t *cmd)
{
	omap3_ext_t		*omap3;
	uintptr_t		base;

	omap3 = (omap3_ext_t *)ext;
	base  = omap3->mmc_base;

	slogf(_SLOGC_SIM_MMC, _SLOG_ERROR, "[%s]ie status %x",  __FUNCTION__,in32(base + OMAP3_MMCHS_IE));

	return (MMC_SUCCESS);
}
static int omap3_command(void *ext, sdio_cmd_t *cmd)
{
	omap3_ext_t		*omap3;
	uintptr_t		base;
	uint32_t		command;
	uint32_t		imask;

	omap3 = (omap3_ext_t *)ext;
	base  = omap3->mmc_base;

	if (cmd->eflags & SDMMC_CMD_INIT) {

		uint32_t	tmp = in32(base + OMAP3_MMCHS_CON);
		out32(base + OMAP3_MMCHS_CON, tmp | CON_INIT);
		delay(10);
		out32(base + OMAP3_MMCHS_CON, tmp);
	}

	/* Clear Status */
	out32(base + OMAP3_MMCHS_STAT, 0x117F8033);

	imask = 0x110f8000;

	command = (cmd->opcode) << 24;
	if (cmd->opcode == 12)
		command |= CMD_TYPE_CMD12;

	if (cmd->eflags & SDMMC_CMD_DATA) {

		command |= omap3->dcmd;
		imask |= INTR_DTO | INTR_DCRC | INTR_DEB;	// Enable all data error interrupts
		imask |= omap3->dmask;	// Data complete interrupt or data ready interrupt
	} else
		imask |= INTR_CC;		// Enable command complete interrupt

	if (cmd->rsptype & MMC_RSP_PRESENT) {

		if (cmd->rsptype & MMC_RSP_136)
			command |= CMD_RSP_TYPE_136;
		else if (cmd->rsptype & MMC_RSP_BUSY)	// Response with busy check
			command |= CMD_RSP_TYPE_48b;
		else
			command |= CMD_RSP_TYPE_48;

		if (cmd->rsptype & MMC_RSP_OPCODE)		// Index check
		{

			command |= CMD_CICE;
		}
		if (cmd->rsptype & MMC_RSP_CRC)		// CRC check
			command |= CMD_CCCE;
	}

	/* Setup the Argument Register and send CMD */
	out32(base + OMAP3_MMCHS_IE,  imask);
	out32(base + OMAP3_MMCHS_ARG, cmd->argument);
	out32(base + OMAP3_MMCHS_CMD, command);

	return (MMC_SUCCESS);
}

static int omap3_cfg_bus(void *ext, uint8_t width)
{
	omap3_ext_t		*omap3;
	uintptr_t		base;
	uint32_t		tmp;

	omap3 = (omap3_ext_t *)ext;
	base  = omap3->mmc_base;

	tmp = in32(base + OMAP3_MMCHS_CON);
	if(width==8){
		out32(base + OMAP3_MMCHS_CON, tmp | CON_DW8 );
	}else{
		out32(base + OMAP3_MMCHS_CON, tmp & ~CON_DW8 );
		tmp = in32(base + OMAP3_MMCHS_HCTL);
		if (width == 4)
			tmp |= HCTL_DTW4;
		else
			tmp &= ~HCTL_DTW4;
		out32(base + OMAP3_MMCHS_HCTL, tmp);
	}

	return (MMC_SUCCESS);
}

static int omap3_clock(void *ext, int *clock)
{
	omap3_ext_t		*omap3;
	uintptr_t		base;
	uint32_t		sysctl,hctl;
	int				clkd;

	omap3 = (omap3_ext_t *)ext;
	base  = omap3->mmc_base;

	clkd = omap3->mmc_clock / (*clock);
	if (omap3->mmc_clock != (*clock) * clkd)
		clkd++;
	*clock = omap3->mmc_clock / clkd;

	sysctl = in32(base + OMAP3_MMCHS_SYSCTL);

	// Stop clock
	sysctl &= ~(SYSCTL_ICE | SYSCTL_CEN | SYSCTL_DTO_MASK);
	sysctl |= SYSCTL_DTO_MAX | SYSCTL_SRC | SYSCTL_SRD;
	out32(base + OMAP3_MMCHS_SYSCTL, sysctl);

	//set high speed
	if(*clock >= 50000000){
		hctl = in32(base + OMAP3_MMCHS_HCTL);
		hctl |= (1<<2);
		out32(base + OMAP3_MMCHS_HCTL,hctl);
	}

	// Enable internal clock
	sysctl &= ~(0x3FF << 6);
	sysctl |= (clkd << 6) | SYSCTL_ICE;
	out32(base + OMAP3_MMCHS_SYSCTL, sysctl);

	// Wait for the clock to be stable
	while ((in32(base + OMAP3_MMCHS_SYSCTL) & SYSCTL_ICS) == 0)
		;

	// Enable clock to the card
	out32(base + OMAP3_MMCHS_SYSCTL, sysctl | SYSCTL_CEN);
	return (MMC_SUCCESS);
}

static int omap3_block_size(void *ext, int blksz)
{
	omap3_ext_t		*omap3;

	omap3 = (omap3_ext_t *)ext;

	if (blksz > 1024)
		return (MMC_FAILURE);

	omap3->blksz = blksz;
	out32(omap3->mmc_base + OMAP3_MMCHS_BLK, omap3->blksz);

	return (MMC_SUCCESS);
}

/*
 * Reset host controller and card
 * The clock should be enabled and set to minimum (<400KHz)
 */
static int omap3_powerup(void *ext)
{
	omap3_ext_t		*omap3;
	uintptr_t		base;
	int				clock;

	omap3 = (omap3_ext_t *)ext;
	base  = omap3->mmc_base;
	// Disable All interrupts
	out32(base + OMAP3_MMCHS_IE, 0);

	// Software reset
	out32(base + OMAP3_MMCHS_SYSCONFIG, SYSCONFIG_SOFTRESET);
	while ((in32(base + OMAP3_MMCHS_SYSSTATUS) & SYSSTATUS_RESETDONE) == 0)
		;

	out32(base + OMAP3_MMCHS_SYSCTL, SYSCTL_SRA);
	while ((in32(base + OMAP3_MMCHS_SYSCTL) & SYSCTL_SRA) != 0)
		;

	out32(base + OMAP3_MMCHS_HCTL, HCTL_SDVS3V0);

	out32(base + OMAP3_MMCHS_CAPA, 
			in32(base + OMAP3_MMCHS_CAPA) | CAPA_VS3V3 | CAPA_VS3V0 | CAPA_VS1V8);

	out32(base + OMAP3_MMCHS_CON, (3 << 9));

	clock = 400 * 1000;		// 400KHz clock

	omap3_clock(omap3, &clock);
	omap_set_bus_mode(omap3, 0);	//set busmode open drain

	out32(base + OMAP3_MMCHS_HCTL, HCTL_SDVS3V0 | HCTL_SDBP);
	out32(base + OMAP3_MMCHS_ISE, 0x117F8033);	// Enable the interrupt signals which we use


	delay(10);
	return (MMC_SUCCESS);
}

int omap3_detect(void *ext)
{
	// Need external logic to detect card
	return (MMC_SUCCESS);
}

static int omap3_powerdown(void *ext)
{
	omap3_ext_t		*omap3;
	uintptr_t		base;

	omap3 = (omap3_ext_t *)ext;
	base  = omap3->mmc_base;

	// Disable all MMCHS interrupt signals
	out32(base + OMAP3_MMCHS_ISE, 0);

	// Disable All interrupts
	out32(base + OMAP3_MMCHS_IE, 0);
	out32(base + OMAP3_MMCHS_ISE, 0);

	// Software reset
	out32(base + OMAP3_MMCHS_SYSCONFIG, SYSCONFIG_SOFTRESET);
	while ((in32(base + OMAP3_MMCHS_SYSSTATUS) & SYSSTATUS_RESETDONE) == 0)
		;

	out32(base + OMAP3_MMCHS_SYSCTL, SYSCTL_SRA);
	while ((in32(base + OMAP3_MMCHS_SYSCTL) & SYSCTL_SRA) != 0)
		;
	return (MMC_SUCCESS);
}

static int omap3_shutdown(void *ext)
{
	omap3_ext_t		*omap3;
	omap3 = (omap3_ext_t *)ext;

	omap3_powerdown(ext);

	munmap_device_io(omap3->mmc_base, OMAP3_MMCHS_SIZE);
	if (omap3->dma_base) {
#ifdef USE_EDMA
		omap3_edma_done(omap3, omap3->dma_rreq);
		omap3_edma_done(omap3, omap3->dma_treq);
		// Unmap the DMA registers
		munmap_device_io(omap3->dma_base, DRA446_EDMA_SIZE);
#else
		dma4_param	*param = (dma4_param *)(omap3->dma_base + DMA4_CCR(omap3->dma_chnl));

		// Disable this DMA event
		param->ccr = 0;

		// Clear all status bits
		param->csr = 0x1FFE;

		// Unmap the DMA registers
		munmap_device_io(omap3->dma_base, OMAP3_DMA4_SIZE);
#endif
	}

	free(omap3);

	return (0);
}

static unsigned omap3_get_syspage_clk(void)
{
	unsigned	item, offset, clock = 0;
	char		*name;
	hwi_tag		*tag;

	item = hwi_find_item(HWI_NULL_OFF, HWI_ITEM_DEVCLASS_DISK, "mmc", NULL);
	if (item == HWI_NULL_OFF)
		return 0;

	offset = item;

	while ((offset = hwi_next_tag(offset, 1)) != HWI_NULL_OFF) {
		tag = hwi_off2tag(offset);
		name = __hwi_find_string(((hwi_tag *)tag)->prefix.name);

		if (strcmp(name, HWI_TAG_NAME_inputclk) == 0)
			clock = ((struct hwi_inputclk *)tag)->clk / ((struct hwi_inputclk *)tag)->div;
	}

	return clock;
}
int omap3_dump_reg(void *ext_hdl){
	sdio_ext_t * ext = (sdio_ext_t *)ext_hdl;
	omap3_ext_t		*omap3 = (omap3_ext_t *)ext->hchdl;
	uint32_t reg_array[] = {
			0x010,0x014,0x024,0x028,0x02C,
			0x030,0x100,0x104,0x108,0x10C,
			0x110,0x114,0x118,0x11C,0x120,
			0x124,0x128,0x12C,0x130,0x134,
			0x138,0x13C,0x140,0x148,0x150,
			0x154,0x158,0x15C,0x1FC
	};
	char *	reg_name[] = {
			"110","114","124","128","12C",
			"130","200","204","208","20C",
			"210","214","218","21C","220",
			"224","228","22C","230","234",
			"238","23C","240","248","250",
			"254","258","25C","2FC"
	};
	int i;
	uint32_t reg = 0;
	for(i=0;i<sizeof(reg_array)/sizeof(reg_array[0]);i++){
		reg = in32(omap3->mmc_base + reg_array[i]);
		if(i!=0 && i%5==0)
				printf("\n");
		printf("[%s]=0x%x\t",reg_name[i],reg);
	}
	printf("\n");
	return (MMC_SUCCESS);
}
/* MMC: Open Drain; SD: Push Pull */
static void omap_set_bus_mode(void *hchdl, int mode)
{
	omap3_ext_t	 *omap3 = (omap3_ext_t	*)hchdl;

	unsigned	base = omap3->mmc_base;
	unsigned	tmp = in32(base + OMAP3_MMCHS_CON) & ~CON_OD;

	printf("omap_set_bus_mode, tmp = 0x%x\r\n", tmp);
	if (mode == 0) {
		tmp |= CON_OD;
	}
	else
	{
		tmp &= 0xFFFE;

	}
	printf("omap_set_bus_mode, tmp = 0x%x\r\n", tmp);

	out32(base + OMAP3_MMCHS_CON, tmp);
}
int	omap3_attach(void *ext_hdl)
{
	sdio_ext_t * ext = (sdio_ext_t *)ext_hdl;

	omap3_ext_t		*omap3 = (omap3_ext_t *)ext->hchdl;
	CONFIG_INFO		*cfg = ext->hc_cfg;
	omap3->mmc_pbase = cfg->IOPort_Base[0];
	ext->hc_irq = omap3->irq	= cfg->IRQRegisters[0];
	if ((omap3->mmc_base =
			mmap_device_io(OMAP3_MMCHS_SIZE, omap3->mmc_pbase))
				== (uintptr_t)MAP_FAILED) {
		slogf (_SLOGC_SIM_MMC, _SLOG_ERROR, "OMAP3 MMCSD: mmap_device_io failed");
		goto fail0;
	}

	// Capability
	//ext->hccap |= MMC_HCCAP_ACMD12 | MMC_HCCAP_BW1 | MMC_HCCAP_BW4 | MMC_HCCAP_BW8;	// 1 bit / 4 bits bus supported
	ext->hccap |= MMC_HCCAP_BW4;	// 4 bits bus supported
	ext->hccap |= MMC_HCCAP_33V | MMC_HCCAP_30V | MMC_HCCAP_18V;
#ifdef USE_EDMA
	if (cfg->NumDMAs > 1 && cfg->NumIOPorts > 1) {
		omap3->dma_treq = cfg->DMALst[0];
		omap3->dma_rreq = cfg->DMALst[1];
		if ((omap3->dma_base = 
			mmap_device_io(DRA446_EDMA_SIZE, cfg->IOPort_Base[1])) == (uintptr_t)MAP_FAILED) {
			slogf (_SLOGC_SIM_MMC, _SLOG_ERROR, "OMAP3 MMCSD: mmap_device_io failed");
			goto fail1;
		}
		ext->hccap |= MMC_HCCAP_DMA;
	}
#else
	if (cfg->NumDMAs > 2 && cfg->NumIOPorts > 1) {
		omap3->dma_chnl = cfg->DMALst[0];
		omap3->dma_treq = cfg->DMALst[1];
		omap3->dma_rreq = cfg->DMALst[2];

		if ((omap3->dma_base = 
			mmap_device_io(OMAP3_DMA4_SIZE, cfg->IOPort_Base[1])) == (uintptr_t)MAP_FAILED) {
			slogf (_SLOGC_SIM_MMC, _SLOG_ERROR, "OMAP3 MMCSD: mmap_device_io failed");
			goto fail1;
		}
		ext->hccap |= MMC_HCCAP_DMA;
	}
#endif
	if ((omap3->mmc_clock = omap3_get_syspage_clk()) == 0)
		omap3->mmc_clock = 96000000;
	omap3->mmc_clock = 96000000;
	ext->handle    = omap3;
	ext->hclock     = omap3->mmc_clock;
	ext->detect    = omap3_detect;
	ext->powerup   = omap3_powerup;
	ext->powerdown = omap3_powerdown;
	ext->ienable	 = omap3_ienable;
	ext->ivalidate	 = omap3_ivalidate;
	ext->iprocess	 = omap3_iprocess;
	ext->command   = omap3_command;
	ext->command_done = omap3_command_done;
	ext->bus_width   = omap3_cfg_bus;
	ext->bus_speed = omap3_clock;
	ext->block_size = omap3_block_size;
	ext->setup_dma = omap3_setup_dma;
	ext->dma_done  = omap3_dma_done;
	ext->setup_pio = omap3_setup_pio;
	ext->pio_done  = omap3_pio_done;
	ext->shutdown  = omap3_shutdown;

	ext->hc_dump_reg = omap3_dump_reg;
	if (!cfg->Description[0])
		strncpy((void *)cfg->Description, "TI OMAP3 MMCHS", sizeof(cfg->Description));
	return (MMC_SUCCESS);

fail0:
	free(omap3);
fail1:
	munmap_device_io(omap3->mmc_base, OMAP3_MMCHS_SIZE);

	return (MMC_FAILURE);
}

#endif

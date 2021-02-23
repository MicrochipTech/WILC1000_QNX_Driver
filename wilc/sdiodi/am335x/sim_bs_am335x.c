/*
 * $QNXLicenseC:
 * Copyright 2008, QNX Software Systems. 
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

// Module Description:  board specific interface

#include <arm/inout.h>
#include <sim_omap3.h>
#include <proto.h>
#include <sim_bs.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <unistd.h>

#include "omap3530.h"

int bs_init(void *ext_hdl)
{
	sdio_ext_t * ext = (sdio_ext_t *)(ext_hdl);
	CONFIG_INFO * cfg = calloc(1,sizeof(CONFIG_INFO));
	if(cfg == NULL){
		return MMC_FAILURE;
	}
	omap3_ext_t	* omap = (omap3_ext_t *)calloc(1,sizeof(omap3_ext_t));
	if(omap == NULL){
		return MMC_FAILURE;
	}
	ext->hchdl = omap;
	//todo:Initialize the soc configure


	if (!cfg->NumIOPorts) {
		cfg->IOPort_Base[0]   = 0x48060100;
		cfg->IOPort_Length[0] = OMAP3_MMCHS_SIZE;
		cfg->IOPort_Base[1]   = DRA446_EDMA_BASE;
		cfg->IOPort_Length[1] = DRA446_EDMA_SIZE;
		cfg->NumIOPorts = 2;
	} else if (cfg->NumIOPorts < 2) {
		slogf (_SLOGC_SIM_MMC, _SLOG_ERROR, "OMAP3 MMCSD: DMA4 base address must be specified");
		return MMC_FAILURE;
	}
	
	if (!cfg->NumIRQs) {
		cfg->IRQRegisters[0] = 64;
		cfg->NumIRQs = 1;
	}

	if (!cfg->NumDMAs) {
		cfg->DMALst[0] = 24;	// DMA request line for MMC1 TX
		cfg->DMALst[1] = 25;	// DMA request line for MMC1 RX
		cfg->NumDMAs = 2;
	} else if (cfg->NumDMAs == 1) {
		cfg->DMALst[1] = cfg->DMALst[1]+1;	// DMA request line for MMC1 RX
		cfg->NumDMAs = 2;
	} else if (cfg->NumDMAs < 2) {
		slogf (_SLOGC_SIM_MMC, _SLOG_ERROR, "OMAP3 MMCSD: DMA channel and Tx/Rx request event must be specified");
		return MMC_FAILURE;
	}
	ext->hc_cfg = cfg;
	if (omap3_attach(ext) != MMC_SUCCESS)
		return MMC_FAILURE;
	ext->hccap &= ~MMC_HCCAP_BW8; //the hardware does not support 8data pin
	ext->tid = cfg->IRQRegisters[0];
	return MMC_SUCCESS;
}

/*****************************************************************************/
/*                                                                           */
/*****************************************************************************/

int bs_dinit(void *ext)
{
	return (MMC_SUCCESS);
}



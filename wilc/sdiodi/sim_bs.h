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

// Module Description:  board specific header file

#ifndef _BS_H_INCLUDED
#define _BS_H_INCLUDED
#include <sys/types.h>

// add new chipset externs here
#define MMCSD_VENDOR_TI_OMAP3
#define USE_EDMA

/* I/O Status definitions */
#define	MMC_SUCCESS				0
#define	MMC_FAILURE				1


#define	MAX_MEM_REGISTERS		9
#define	MAX_IO_PORTS			20
#define	MAX_IRQS				6
#define	MAX_DMA_CHANNELS		6

struct Config_Info {
	//struct Device_ID	Device_ID;			/* Device ID information */
	//union Bus_Access	BusAccess;			/* Info to allow config. access */

	ulong_t				NumMemWindows;		/* Num memory windows */
	ulong_t				MemBase[MAX_MEM_REGISTERS];  	/* Memory window base */
	ulong_t				MemLength[MAX_MEM_REGISTERS];	/* Memory window length */
	ulong_t				MemAttrib[MAX_MEM_REGISTERS];	/* Memory window Attrib */

	ulong_t				NumIOPorts;						/* Num IO ports */
	ulong_t				IOPort_Base[MAX_IO_PORTS];		/* I/O port base */
	ulong_t				IOPort_Length[MAX_IO_PORTS];	/* I/O port length */

	ulong_t				NumIRQs;						/* Num IRQ info */
	ulong_t				IRQRegisters[MAX_IRQS];			/* IRQ list */
	ulong_t				IRQAttrib[MAX_IRQS];			/* IRQ Attrib list */

	ulong_t				NumDMAs;						/* Num DMA channels */
	ulong_t				DMALst[MAX_DMA_CHANNELS];	 	/* DMA list */
	ulong_t				DMAAttrib[MAX_DMA_CHANNELS];	/* DMA Attrib list */

	char				Description[33];				/* Device specific desc */
	uchar_t				Reserved1[3];					/* Reserved */
};

typedef struct Config_Info			CONFIG_INFO;

typedef struct _bs_ext {
	CONFIG_INFO cfg;
}bsext;

/*
 * Interrupt status
 */
#define	MMC_INTR_NONE			0
#define	MMC_INTR_COMMAND		(1 << 0)		// Command complete
#define	MMC_INTR_DATA			(1 << 1)		// Data complete
#define	MMC_INTR_RBRDY			(1 << 2)		// Read buffer ready, for PIO only
#define	MMC_INTR_WBRDY			(1 << 3)		// Write buffer ready, for PIO only
#define	MMC_INTR_CARDINS		(1 << 4)		// Card insertion detected
#define	MMC_INTR_CARDRMV		(1 << 5)		// Card removal detected
#define	MMC_INTR_OVERCURRENT	(1 << 6)		// Over current detected
#define	MMC_INTR_CARD			(MMC_INTR_CARDINS | MMC_INTR_CARDRMV | MMC_INTR_OVERCURRENT)
#define	MMC_INTR_ERROR			(1 << 15)		// Error detected
#define	MMC_ERR_DATA_END		(1 << 16)		// Data End Bit Error
#define	MMC_ERR_DATA_CRC		(1 << 17)		// Data CRC Error
#define	MMC_ERR_DATA_TO			(1 << 18)		// Data Timeout Error
#define	MMC_ERR_CMD_IDX			(1 << 19)		// Command Index Rrror
#define	MMC_ERR_CMD_END			(1 << 20)		// Command End Bit Rrror
#define	MMC_ERR_CMD_CRC			(1 << 21)		// Command CRC Rrror
#define	MMC_ERR_CMD_TO			(1 << 22)		// Command Timeout Rrror

int bs_init(void *ext);
int bs_dinit(void *ext);

#endif

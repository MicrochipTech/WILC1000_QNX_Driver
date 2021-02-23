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



#ifndef		_PROT_INCLUDED
#define		_PROT_INCLUDED

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atomic.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/neutrino.h>
#include <sys/cache.h>

#include <sim_bs.h>
#include "sdio.h"

/* MultiMediaCard Command definitions */
/* An 'S' after the definition means that this command is available in SPI mode */
/* SPI commands are a subset of the MMC definition */

#define	MMC_GO_IDLE_STATE			0		/* S */
#define	MMC_SEND_OP_COND			1		/* S */
#define	MMC_ALL_SEND_CID			2
#define	MMC_SET_RELATIVE_ADDR		3
#define	MMC_SET_DSR					4
#define	MMC_SEL_DES_CARD			7
#define	MMC_IF_COND					8
#define	MMC_SEND_CSD				9		/* S */
#define	MMC_SEND_CID				10		/* S */
#define	MMC_READ_DAT_UNTIL_STOP		11
#define	MMC_STOP_TRANSMISSION		12
#define	MMC_SEND_STATUS				13		/* S */
#define	MMC_GO_INACTIVE_STATE		15
#define	MMC_SET_BLOCKLEN			16		/* S */
#define	MMC_READ_SINGLE_BLOCK		17		/* S */
#define	MMC_READ_MULTIPLE_BLOCK		18
#define	MMC_WRITE_DAT_UNTIL_STOP	20
#define	MMC_WRITE_BLOCK				24		/* S */
#define	MMC_WRITE_MULTIPLE_BLOCK	25
#define	MMC_PROGRAM_CID				26
#define	MMC_PROGRAM_CSD				27		/* S */
#define	MMC_SET_WRITE_PROT			28		/* S */
#define	MMC_CLR_WRITE_PROT			29		/* S */
#define	MMC_SEND_WRITE_PROT			30		/* S */
#define	MMC_TAG_SECTOR_START		32		/* S */
#define	MMC_TAG_SECTOR_END			33		/* S */
#define	MMC_UNTAG_SECTOR			34		/* S */
#define	MMC_TAG_ERASE_GROUP_START	35		/* S */
#define	MMC_TAG_ERASE_GROUP_END		36		/* S */
#define	MMC_UNTAG_ERASE_GROUP		37		/* S */
#define	MMC_ERASE					38		/* S */
#define	MMC_FAST_IO					39
#define	MMC_GO_IRQ_STATE			40
#define	MMC_LOCK_UNLOCK				42		/* S */
#define	MMC_APP_CMD					55		/* S */
#define	MMC_GEN_CMD					56		/* S */
#define	MMC_READ_OCR				58		/* S */
#define	MMC_CRC_ON_OFF				59		/* S */

/* SD Command definitions */
#define	SD_SET_BUS_WIDTH			6
#define	SD_SEND_OP_COND				41
#define	SD_SEND_SCR					51

/* SDIO Command definitions */
#define	IO_SEND_OP_COND				5



/* Card Status Response Bits */

#define	MMC_OUT_OF_RANGE			(1 << 31)
#define	MMC_ADDRESS_ERROR			(1 << 30)
#define	MMC_BLOCK_LEN_ERROR			(1 << 29)
#define	MMC_ERASE_SEQ_ERROR			(1 << 28)
#define	MMC_ERASE_PARAM				(1 << 27)
#define	MMC_WP_VIOLATION			(1 << 26)
#define	MMC_CARD_IS_LOCKED			(1 << 25)
#define	MMC_LOCK_UNLOCK_FAILED		(1 << 24)
#define	MMC_COM_CRC_ERROR			(1 << 23)
#define	MMC_ILLEGAL_COMMAND			(1 << 22)
#define	MMC_CARD_ECC_FAILED			(1 << 21)
#define	MMC_CC_ERROR				(1 << 20)
#define	MMC_ERROR					(1 << 19)
#define	MMC_UNDERRUN				(1 << 18)
#define	MMC_OVERRUN					(1 << 17)
#define	MMC_CID_CSD_OVERWRITE		(1 << 16)
#define	MMC_WP_ERASE_SKIP			(1 << 15)
#define	MMC_CARD_ECC_DISABLED		(1 << 14)
#define	MMC_ERASE_RESET				(1 << 13)
/* Bits 9-12 define the CURRENT_STATE */
#define	MMC_IDLE					(0 << 9)
#define	MMC_READY					(1 << 9)
#define	MMC_IDENT					(2 << 9)
#define	MMC_STANDBY					(3 << 9)
#define	MMC_TRAN					(4 << 9)
#define	MMC_DATA					(5 << 9)
#define	MMC_RCV						(6 << 9)
#define	MMC_PRG						(7 << 9)
#define	MMC_DIS						(8 << 9)
/* End CURRENT_STATE */
#define	MMC_READY_FOR_DATA			(1 << 8)
#define	MMC_APP_CMD_S				(1 << 5)

/* SPI Mode Response R1 format */

#define	MMC_PARAM_ERROR				(1 << 6)
#define	MMC_SADDRESS_ERROR			(1 << 5)
#define	MMC_SERASE_SEQ_ERROR		(1 << 4)
#define	MMC_SCOM_CRC_ERROR			(1 << 3)
#define	MMC_SILLEGAL_COMMAND		(1 << 2)
#define	MMC_SERASE_RESET			(1 << 1)
#define	MMC_IDLE_STATE				(1 << 0)

/* SPI Mode Response R2 format */
/* First byte is the same as R1 format */
#define	MMC_SOUT_OF_RANGE			(1 << 7)
#define	MMC_SERASE_PARAM			(1 << 6)
#define	MMC_SWP_VIOLATION			(1 << 5)
#define	MMC_SCARD_ECC_FAILED		(1 << 4)
#define	MMC_SCC_ERROR				(1 << 3)
#define	MMC_SERROR					(1 << 2)
#define	MMC_SWP_ERASE_SKIP			(1 << 1)
#define	MMC_SCARD_IS_LOCKED			(1 << 0)

/* I/O Definitions for target ID */
#define	MMC_TARGET_MMC				0
#define	MMC_TARGET_MAS				1

/* I/O Flag definitions */
#define	MMC_DIR_NONE			0
#define	MMC_DIR_IN				(1 << 0)
#define	MMC_DIR_OUT				(1 << 1)	
#define	MMC_CRC7				(1 << 2)
#define	MMC_CRC16				(1 << 3)
#define	MMC_DIR_MASK			(MMC_DIR_IN | MMC_DIR_OUT)

/* I/O Status definitions */
#define	MMC_SUCCESS				0
#define	MMC_FAILURE				1
#define	MMC_DATA_OVERRUN		2
#define	MMC_BAD_FLAG			3
#define	MMC_NOT_PRESENT			4
#define	MMC_TIMEOUT				5
#define	MMC_ALLOC_FAILED		6
#define	MMC_INVALID_HANDLE		7
#define	MMC_COMMAND_FAILURE		8
#define	MMC_READ_ERROR			9
#define	MMC_WRITE_ERROR			10




#define	MMC_RSP_PRESENT	(1 << 0)
#define	MMC_RSP_136		(1 << 1)	/* 136 bit response */
#define	MMC_RSP_CRC		(1 << 2)	/* expect valid crc */
#define	MMC_RSP_BUSY	(1 << 3)	/* card may send busy */
#define	MMC_RSP_OPCODE	(1 << 4)	/* response contains opcode */

#define	MMC_RSP_NONE	(0)
#define	MMC_RSP_R1		(MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)
#define	MMC_RSP_R1B		(MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE | MMC_RSP_BUSY)
#define	MMC_RSP_R2		(MMC_RSP_PRESENT | MMC_RSP_136 | MMC_RSP_CRC)
#define	MMC_RSP_R3		(MMC_RSP_PRESENT)
#define	MMC_RSP_R6		(MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)
#define	MMC_RSP_R7		(MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)

#define	SDIO_RSP_R4		(MMC_RSP_PRESENT)
#define	SDIO_RSP_R5		(MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)

#define	MAX_SDIO_FUNCTIONS	8

/* SDIO structure */
typedef	struct	_sdio_cmd_t {
	uint8_t		opcode;			// command code
	uint8_t		rsptype;		// response type
	uint16_t	eflags;			// flags
#define	SDMMC_CMD_NONE			(0 << 0)	// nothing special
#define	SDMMC_CMD_INIT			(1 << 0)	// initialize sequence required
#define	SDMMC_CMD_PPL			(1 << 1)	// Push-pull command
#define	SDMMC_CMD_DATA			(1 << 4)	// command expect data
#define	SDMMC_CMD_DATA_MULTI	(1 << 5)	// multi-blocks data expected
#define	SDMMC_CMD_DATA_IN		(1 << 6)	// data read
#define	SDMMC_CMD_DATA_DMA		(1 << 7)	// DMA is expected for data transfer
#define	SDMMC_CMD_INTR			(1 << 8)	// command complete interrupt expected
	uint32_t	argument;		// command argument
	uint8_t		*data;
	int			blkcnt;			// block count;
	int			size;			// block size or total byte count if block count is 0
	uint32_t	resp[4];
//	int			results;
} sdio_cmd_t;

#define MAX_SDIO_FUNCTIONS	8

typedef struct _sdio_ext_t {
	int					hc_iid;
	int					hc_irq;
	struct sigevent		event;		/* has to be the first element */
#define	SDIO_PULSE		5
	int					chid;		/* channel id */
	int					coid;		/* connection id */
	int					tid;		/* thread id */
	int					state;		/* current state */
#define	SDIO_STATE_POWEROFF	0		/* power off */
#define	SDIO_STATE_POWERUP	1		/* power up, but not initialized yet */
#define	SDIO_STATE_ENUM		2		/* card enumerate */
#define	SDIO_STATE_READY	3		/* card ready */
#define	SDIO_STATE_COMMAND	4		/* card wait for command complete */
#define	SDIO_STATE_DATA		5		/* card wait for data complete */

	int					nfunc;		/* Number of function */

	uint8_t				dev_name[256 + 4];	// device name
	uint16_t			dev_vid;			// vendor ID
	uint16_t			dev_did;			// device ID
	uint8_t				bic;		/* bus interface control register */
	uint8_t				capability;	/* Card capability */
	uint8_t				speed;		/* High-Speed */
	uint8_t				rsv1;		/* Reserved */
	uint32_t			cisptr[MAX_SDIO_FUNCTIONS];
	sdio_dev_t			func[MAX_SDIO_FUNCTIONS];
	uint16_t			blksz[MAX_SDIO_FUNCTIONS];

	void				*hchdl;		/* Host controller handle */
	pthread_mutex_t		mutex;		/* Mutex */
	struct cache_ctrl	cachectl;
	sdio_cmd_t			*cmd;		/* Current pending command */
	int					wait_srv;	/* Wait for card service interrupt */
	int					wait_cmd;	/* Wait for command complete interrupt */
	int					card_intr;	/* Card interrupt */
	unsigned			pend_srv;	/* Pending service event */
#define	MMC_HCCAP_HS		(1 << 0)		// Host support high speed
#define	MMC_HCCAP_DMA		(1 << 1)		// Host support DMA
#define	MMC_HCCAP_18V		(1 << 2)		// Host support 1.8V
#define	MMC_HCCAP_30V		(1 << 3)		// Host support 3.0V
#define	MMC_HCCAP_33V		(1 << 4)		// Host support 3.3V
#define	MMC_HCCAP_BW1		(1 << 5)		// Host support 1 bit bus (mandatory)
#define	MMC_HCCAP_BW4		(1 << 6)		// Host support 4 bit bus (mandatory)
#define	MMC_HCCAP_BW8		(1 << 7)		// Host support 8 bit bus
#define	MMC_HCCAP_ACMD12	(1 << 8)		// Host support auto-stop command(ACMD12)
#define	MMC_HCCAP_CD_INTR	(1 << 9)		// Host support card detect interrupt
#define	MMC_HCCAP_NOCD_BUSY	(1 << 10)		// Host has card busy detect bug
	uint32_t			hccap;		/* Capability of host controller */

	uint32_t			hclock;		/* host controller base clock */
	uint32_t			oclock;		/* operation clock */

	uint32_t			eflags;

	int					istatus;


	void				*bs;			// hardware specific pointer
	char				*opts;

	void				*handle;

	void				(*hdl_init)(void *);	// something has to be initialized in the SDIO event handler

	int					(*detect)(void *);		// card status
	int					(*powerup)(void *);		// powerup MMC/SD HC
	int					(*powerdown)(void *);	// powerdown MMC/SD HC

	int					(*command)(void *, sdio_cmd_t *);		// send command
	int					(*command_done)(void *, sdio_cmd_t *);	// command done
	int					(*ienable)(void *, int irq, int);			// enable/disable interrupt
	int					(*ivalidate)(void *, int irq, int busy);		// validate interrupt
	int					(*iprocess)(void *, sdio_cmd_t *cmd);	// process interrupt
	int					(*setup_dma)(void *, paddr_t, int, int);	// DMA read/write setup
	int					(*dma_done)(void *, int dir);			// DMA xfer complete
	int					(*setup_pio)(void *, char *buf, int len, int dir);	// PIO read/write setup
	int					(*pio_done)(void *, char *buf, int len, int dir);	// complete
	int					(*block_size)(void *, int blksz);		// set block size
	int					(*bus_speed)(void *, int *speed);		// set bus speed, in HZ
	int					(*bus_width)(void *, uint8_t width);	// set bus_width, 1 or 4

	int					(*shutdown)(void *);		// Shutdown
	int					(*get_mask)(void *);		// Get current SDIO interrupt mask status
	int					(*hc_dump_reg)(void *);
	CONFIG_INFO	*		hc_cfg;
        int verbose;
        int source_clock; //TODO: cmd line params
} sdio_ext_t;
/*
 * Host controller capability bits defination
 */
#define	SDMMC_CAP_DMA			(1 << 0)	// controller support DMA
#define	SDMMC_CAP_PIO			(1 << 1)	// controller support PIO

#define	SDMMC_CAP_18V			(1 << 2)	// 1.8v is supported
#define	SDMMC_CAP_30V			(1 << 3)	// 3.0v is supported
#define	SDMMC_CAP_33V			(1 << 3)	// 3.3v is supported

#define	SDMMC_CAP_BW1			(1 << 5)	// 1 bit bus supported
#define	SDMMC_CAP_BW4			(1 << 6)	// 4 bit bus supported
#define	SDMMC_CAP_BW8			(1 << 7)	// 8 bit bus supported

#define	SDMMC_CAP_ACMD12		(1 << 10)	// auto stop command(ACMD12) supported
#define	SDMMC_CAP_HS			(1 << 11)	// High speed device supported


/*
 * Card extra flag bits defination
 */
#define	SDMMC_EFLAG_WP			(1 << 0)	// Write protected


/*
 * Interrupt status returned from host controller
 */
#define SDMMC_INT_NONE			0
#define SDMMC_INT_COMMAND		(1 << 0)		// Command complete
#define SDMMC_INT_DATA			(1 << 1)		// Data complete
#define SDMMC_INT_RBRDY			(1 << 2)		// Read buffer ready, for PIO only
#define SDMMC_INT_WBRDY			(1 << 3)		// Write buffer ready, for PIO only
#define SDMMC_INT_CARDINS		(1 << 4)		// Card insertion detected
#define SDMMC_INT_CARDRMV		(1 << 5)		// Card removal detected
#define SDMMC_INT_SERVICE		(1 << 6)		// Card service
#define SDMMC_INT_OVERCURRENT	(1 << 7)		// Over current detected
#define SDMMC_INT_CARD			(MMC_INTR_CARDINS | MMC_INTR_CARDRMV | MMC_INTR_OVERCURRENT)
#define SDMMC_INT_ERRDE			(1 << 16)		// Data End Bit Error
#define SDMMC_INT_ERRDC			(1 << 17)		// Data CRC Error
#define SDMMC_INT_ERRDT			(1 << 18)		// Data Timeout Error
#define SDMMC_INT_ERRCI			(1 << 19)		// Command Index Rrror
#define SDMMC_INT_ERRCE			(1 << 20)		// Command End Bit Rrror
#define SDMMC_INT_ERRCC			(1 << 21)		// Command CRC Rrror
#define	SDMMC_INT_ERRCT			(1 << 22)		// Command Timeout Rrror
#define SDMMC_INT_ERROR			(SDMMC_INT_ERRDE | \
									SDMMC_INT_ERRDC | \
									SDMMC_INT_ERRDT | \
									SDMMC_INT_ERRCI | \
									SDMMC_INT_ERRCE | \
									SDMMC_INT_ERRCC | \
									SDMMC_INT_ERRCT)

#define	MAKE_SDIO_OFFSET(x)		((uint32_t)((uint32_t)(x)<<9))
#define MAKE_SDIO_OP_CODE(x)	((uint32_t)((uint32_t)(x)<<26))
#define MAKE_SDIO_BLOCK_MODE(x)	((uint32_t)((uint32_t)(x)<<27))
#define MAKE_SDIO_FUNCTION(x)	((uint32_t)((uint32_t)(x)<<28))
#define MAKE_SDIO_DIR(x)		((uint32_t)((uint32_t)(x)<<31))

#define	SDIO_CARD_CAP_SDC		(1 << 0)		// Card supports direct commands during data transfer
#define	SDIO_CARD_CAP_SMB		(1 << 1)		// Card supports multi-block
#define	SDIO_CARD_CAP_SRW		(1 << 2)		// Card supports read wait
#define	SDIO_CARD_CAP_SBS		(1 << 3)		// Card supports suspend/resume
#define	SDIO_CARD_CAP_S4MI		(1 << 4)		// Card supports interrupt between blocks of data in 4-bit SD mode
#define	SDIO_CARD_CAP_E4MI		(1 << 5)		// Enable interrupt between blocks of data in 4-bit SD mode
#define	SDIO_CARD_CAP_LSC		(1 << 6)		// Card is a low-speed card
#define	SDIO_CARD_CAP_4BLS		(1 << 7)		// 4-bit support for low-speed card

extern int	sdio_start(void *hdl);
extern int	sdio_send_command(void *hdl, sdio_cmd_t *cmd);
extern int	sdio_read_cis(sdio_ext_t *sdio, uint8_t func, uint8_t cistpl, uint8_t *buf, int *len);
extern int	sdio_set_blksz(void *hdl, int func, int blksz);
extern int	sdio_slogf(const int minVerbose, const char *fmt, ...);

#define	sdio_cmd52_read(h, o, f, d)		sdio_read_ioreg(h, f, o, d)
#define	sdio_cmd52_write(h, o, f, d)	sdio_write_ioreg(h, f, o, d)

#endif


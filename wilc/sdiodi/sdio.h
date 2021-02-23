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

#ifndef		_SDIO_INCLUDED
#define		_SDIO_INCLUDED
#include <proto.h>
#include <stdint.h>

//#include <sys/cfg.h>

#define	SDIO_FIXED_ADDRESS		0x0
#define	SDIO_BLOCK_MODE			0x1

/*
 * SDIO standard function interface code
 */
#define	SDIO_CLASS_NONE		0x00
#define	SDIO_CLASS_UART		0x01	/* SDIO Standard UART */
#define	SDIO_CLASS_BT_A		0x02	/* SDIO Type-A for Bluetooth standard interface */
#define	SDIO_CLASS_BT_B		0x03	/* SDIO Type-B for Bluetooth standard interface */
#define	SDIO_CLASS_GPS		0x04	/* SDIO GPS standard interface */
#define	SDIO_CLASS_CAMERA	0x05	/* SDIO Camera standard interface */
#define	SDIO_CLASS_PHS		0x06	/* SDIO PHS standard interface */
#define	SDIO_CLASS_WLAN		0x07	/* SDIO WLAN interface */
#define	SDIO_CLASS_ATA		0x08	/* SDIO-ATA standard interface */

/* SDIO Interface Registers */
#define	SDIO_CCCR_SDIO_REV_REG		0x00
#define	SDIO_SD_SPEC_REV_REG		0x01
#define	SDIO_IO_ENABLE_REG			0x02
#define	SDIO_IO_READY_REG			0x03
#define	SDIO_INT_ENABLE_REG			0x04
#define	SDIO_INT_PENDING_REG		0x05
#define	SDIO_IO_ABORT_REG			0x06
#define	SDIO_BUS_INTERFACE_CONTROL_REG	0x07
#define	SDIO_CARD_CAPABILITY_REG	0x08
#define	SDIO_COMMON_CIS_POINTER_0_REG	0x09
#define	SDIO_COMMON_CIS_POINTER_1_REG	0x0A
#define	SDIO_COMMON_CIS_POINTER_2_REG	0x0B
#define	SDIO_BUS_SUSPEND_REG		0x0C
#define	SDIO_FUNCTION_SELECT_REG	0x0D
#define	SDIO_EXEC_FLAGS_REG			0x0E
#define	SDIO_READY_FLAGS_REG		0x0F
#define	SDIO_POWER_CONTROL_REG		0x12
#define	SDIO_HIGH_SPEED_REG			0x13

#define	SDIO_FN_CSA_REG(x)				(0x100 * (x) + 0x00)
#define SDIO_FN_CIS_POINTER_0_REG(x)	(0x100 * (x) + 0x09)
#define SDIO_FN_CIS_POINTER_1_REG(x)	(0x100 * (x) + 0x0A)
#define SDIO_FN_CIS_POINTER_2_REG(x)	(0x100 * (x) + 0x0B)
#define	SDIO_FN_BLOCK_SIZE_0_REG(x)		(0x100 * (x) + 0x10)
#define	SDIO_FN_BLOCK_SIZE_1_REG(x)		(0x100 * (x) + 0x11)

/* SDIO CIS format */
#define	SDIO_CISTPL_NULL			0x00	// NULL tuple
#define	SDIO_CISTPL_CHECKSUM		0x10	// Checksum control
#define	SDIO_CISTPL_VERS_1			0x15	// Level 1 version/product-information
#define	SDIO_CISTPL_ALTSTR			0x16	// The Alternate Language String Tuple
#define	SDIO_CISTPL_MANFID			0x20	// Manufacture Identification String Tuple
#define	SDIO_CISTPL_FUNCID			0x21	// Function Identification Tuple
#define	SDIO_CISTPL_FUNCE			0x22	// Function Extensions
#define	SDIO_CISTPL_SDIO_STD		0x91	// Additional information
#define	SDIO_CISTPL_SDIO_EXT		0x92	// Reserved for future use
#define	SDIO_CISTPL_END				0xFF	// The End-of-chain Tuple


typedef struct _sdio_dev_t {
	uint16_t	vid;	// Vendor ID
	uint16_t	did;	// Device ID
	uint8_t		ccd;	// Class code
	int8_t		fun;	// Function number
} sdio_dev_t;

typedef void (*interruptCb) (void);

extern int	sdio_intr_validate(void *hdl, int irq, int busy);
extern int	sdio_intr_enable(void *hdl, int enable);
extern int	sdio_power(void *hdl, int powerup);
extern int	sdio_detect(void *hdl);
extern int	sdio_bus_speed(void *hdl, int *speed);
extern int	sdio_bus_width(void *hdl, uint8_t width);

extern int	sdio_enable_func(void *hdl, sdio_dev_t *dev, uint16_t blksz);
extern int sdio_attach_device(void *hdl,int(*dev_attach)(void *));

extern int	sdio_func_intr(void *hdl, uint8_t func, int enable);

extern int	sdio_read_ioreg(void *hdl, uint8_t fn, int reg, uint8_t *data);
extern int	sdio_write_ioreg(void *hdl, uint8_t fn, int reg, uint8_t data);

extern int	sdio_set_ioreg(void *hdl, uint8_t fn, int reg, uint8_t bits);
extern int	sdio_clr_ioreg(void *hdl, uint8_t fn, int reg, uint8_t bits);

extern int	sdio_read_iomem(void *hdl, uint8_t fn, uint32_t address,
				uint8_t opcode, uint32_t blkcnt, uint32_t blksz, uint8_t *buffer, off64_t paddr);
extern int	sdio_write_iomem(void *hdl, uint8_t fn, uint32_t address,
				uint8_t opcode, uint32_t blkcnt, uint32_t blksz, uint8_t *buffer, off64_t paddr);

extern int	sdio_event_get(void *hdl, int wait);

extern int	sdio_get_mask(void *hdl);

extern int	sdio_stop(void *hdl);

extern int sdio_init(void **hdl);
extern int sdio_intr_callback_register(interruptCb cb);


#define	SDIO_SUCCESS		0
#define	SDIO_FAILURE		(-1)

/*
 * Interrupt validate function return value 
 */
#define	SDIO_INTR_NONE		0	// Invalid interrupt
#define	SDIO_INTR_CARD		1	// Card service interrupt, should be handled by SDIO client driver
#define	SDIO_INTR_DETECT	2	// Card detect interrupt
#define	SDIO_INTR_SDIO		3	// SDIO interrupt, should be handled by SDIO stack

/*
 * Host controller capability bits defination
 */
#define	SDMMC_CAP_DMA			(1 << 0)	// controller support DMA
#define	SDMMC_CAP_PIO			(1 << 1)	// controller support PIO


#endif


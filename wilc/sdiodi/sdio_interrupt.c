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


int sdio_intr_validate(void *hdl, int irq, int busy)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;

	return sdio->ivalidate(sdio->hchdl, irq, busy);
}

int sdio_intr_enable(void *hdl, int enable)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;

	sdio->ienable(sdio->hchdl, SDIO_INTR_CARD, enable);

	return (MMC_SUCCESS);
}

int sdio_get_mask(void *hdl)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;

	return sdio->get_mask(sdio->hchdl);
}


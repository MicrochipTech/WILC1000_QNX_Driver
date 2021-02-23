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

struct _sdhc {
	uint16_t	vid;
	uint16_t	did;
	void		*(*init)(void *, void *);
};
#if 0
static struct _sdhc sdhc_support_list[] = {
#ifdef __X86__
	{ 0x8086, 0x811e, sdhci_init },
	{ 0x8086, 0x811d, sdhci_init },
	{ 0x8086, 0x811c, sdhci_init },
	{ 0x1095, 0x0670, sdhci_init },
#endif
#ifdef __SH__
	{ 0x10ee, 0x9411, hbsdc_init },
#endif
	{ 0, 0, 0 }
};
#endif
#if 0
void *sdio_init(void * (*hc_init)(void *, void *), void *cfg)
{
	sdio_ext_t			*sdio;
	struct _sdhc		*sdhc;
	struct Config_Info	*hccfg = (struct Config_Info *)cfg;

	if ((sdio = calloc(1, sizeof(sdio_ext_t))) == NULL)
		return (NULL);

	if (hc_init) {
		if ((sdio->hchdl = hc_init(sdio, cfg)) != NULL) {
			/*
			 * Start SDIO thread
	 		 */
			if (sdio_start(sdio) != SDIO_SUCCESS) {
				sdio->shutdown(sdio->hchdl);
				goto fail1;
			}

			return (sdio);
		}
	} else {
		for (sdhc = sdhc_support_list; sdhc->vid != 0; sdhc++) {
			hccfg->Device_ID.DevID = (sdhc->did << 16) | sdhc->vid;
			if ((sdio->hchdl = sdhc->init(sdio, cfg)) != NULL) {
				/*
				 * Start SDIO thread
		 		 */
				if (sdio_start(sdio) != SDIO_SUCCESS) {
					sdio->shutdown(sdio->hchdl);
					goto fail1;
				}

				return (sdio);
			}
		}
	}

fail1:
	free(sdio);
	return (NULL);
}
#else
int sdio_init(void **hdl)
{
	uint8_t context_calloc = 0;

	if(*hdl == NULL){
		if ((*hdl = calloc(1, sizeof(sdio_ext_t))) == NULL)
			return (SDIO_FAILURE);
		context_calloc = 1;
	}
	sdio_ext_t	*sdio= *hdl;

	if (bs_init(sdio) != 0) {
		goto fail1;
	}
	sdio->handle = (void*)sdio;
	/*
	 * Start SDIO thread
	 */
	if (sdio_start(sdio) != SDIO_SUCCESS) {
		sdio->shutdown(sdio->hchdl);
		goto fail1;
	}
	return (SDIO_SUCCESS);
fail1:
	if(context_calloc){
		free(sdio);
	}
	return (SDIO_FAILURE);
}
#endif

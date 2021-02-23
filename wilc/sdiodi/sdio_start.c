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

extern void *sdio_event_handler(void *data);

int sdio_start(void *hdl)
{
	pthread_attr_t		attr;
	struct sched_param	param;
	sdio_ext_t			*sdio = (sdio_ext_t *)hdl;

	if ((sdio->chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)) == -1)
		return (MMC_FAILURE);

	if ((sdio->coid = ConnectAttach(0, 0, sdio->chid, _NTO_SIDE_CHANNEL, 0)) == -1)
		goto fail1;

	if (pthread_mutex_init(&sdio->mutex, NULL) == -1)
		goto fail2;

	if (sdio->eflags & SDMMC_CAP_DMA) {
		sdio->cachectl.fd = NOFD;

		if (cache_init(0, &sdio->cachectl, NULL) == -1) {
			fprintf(stderr, "sdio_start: cache_init: %d", errno);
			goto fail3;
		}
	}

	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_RR);

	int x1 = sched_get_priority_min(SCHED_RR);
	int x2 = sched_get_priority_min(SCHED_RR);

	param.sched_priority = 21;
	pthread_attr_setschedparam(&attr, &param);
	pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, 8192);

	sdio->event.sigev_notify   = SIGEV_PULSE;
	sdio->event.sigev_coid     = sdio->coid;
	sdio->event.sigev_code     = SDIO_PULSE;
	sdio->event.sigev_priority = 21;

	if( ( sdio->hc_iid = InterruptAttachEvent( sdio->hc_irq, &sdio->event, _NTO_INTR_FLAGS_TRK_MSK ) ) == -1 ) {
		fprintf(stderr, "sdio_start:  Unable to attach hc interrupt %d.\n",sdio->hc_irq);
		goto fail4;
	}

	/* Create SDIO event handler */
	if (pthread_create(&sdio->tid, &attr, (void *)sdio_event_handler, hdl)) {
		fprintf(stderr, "sdio_start:  Unable to create event handler\n");
		goto fail4;
	}

	sdio->state = SDIO_STATE_POWEROFF;

	return MMC_SUCCESS;

fail4:
	cache_fini(&sdio->cachectl);
fail3:
	pthread_mutex_destroy(&sdio->mutex);
fail2:
	ConnectDetach(sdio->coid);
fail1:
	ChannelDestroy(sdio->chid);

	return (MMC_FAILURE);
}


int sdio_stop(void *hdl)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;

	sdio->shutdown(sdio->hchdl);

	pthread_cancel(sdio->tid);
	pthread_join(sdio->tid, NULL);

	if (sdio->eflags & SDMMC_CAP_DMA)
		cache_fini(&sdio->cachectl);

	pthread_mutex_destroy(&sdio->mutex);

	ConnectDetach(sdio->coid);
	ChannelDestroy(sdio->chid);

	free(sdio);

	return (MMC_SUCCESS);
}


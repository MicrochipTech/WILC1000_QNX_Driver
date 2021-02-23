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

#include <sys/slog.h>
#include <sys/slogcodes.h>

#include "proto.h"


interruptCb g_intr_cb = NULL;
int g_report_to_drv = 0;


int sdio_intr_callback_register(interruptCb cb)
{
	g_intr_cb = cb;


	return (SDIO_SUCCESS);
}

static void sdio_interrupt(sdio_ext_t *sdio)
{
	int ret = sdio->ivalidate(sdio->hchdl,0,0);
	if (ret == SDIO_INTR_CARD)
	{
		if (sdio->card_intr == 1) {
			pthread_sleepon_lock();
			sdio->card_intr++;
			pthread_sleepon_signal(&sdio->card_intr);
			pthread_sleepon_unlock();
		}
	}

	sdio->istatus = sdio->iprocess(sdio->hchdl, sdio->cmd);

	//slogf(99,1,"%s istatus = 0x%x", __FUNCTION__, sdio->istatus);
	if (sdio->istatus) {
		if (sdio->istatus & ~SDMMC_INT_SERVICE) {
			if (sdio->wait_cmd == 1) {
				pthread_sleepon_lock();
				sdio->wait_cmd++;
				pthread_sleepon_signal(&sdio->wait_cmd);
				pthread_sleepon_unlock();
			}
		}
		if (sdio->istatus & SDMMC_INT_SERVICE) {
			if (sdio->wait_srv == 1) {
				pthread_sleepon_lock();
				sdio->wait_srv++;
				printf("[sdio_interrupt] issue srv\n");
				pthread_sleepon_signal(&sdio->wait_srv);
				pthread_sleepon_unlock();
			} else {
				atomic_add(&sdio->pend_srv, 1);
			}
		}
	}

}

int sdio_event_get(void *hdl, int wait)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	int			ret = SDIO_SUCCESS;

	sdio->card_intr = 1;

	pthread_sleepon_lock();
	sdio->ienable(sdio->hchdl, SDIO_INTR_SDIO, 1);
	if (pthread_sleepon_timedwait(&sdio->card_intr, 1 * 1000 * 1000) != EOK) {
		sdio->ienable(sdio->hchdl, SDIO_INTR_SDIO, 0);
		pthread_sleepon_unlock();
		ret = SDIO_FAILURE;
	}
	else
	{
		sdio->ienable(sdio->hchdl, SDIO_INTR_SDIO, 0);
		pthread_sleepon_unlock();

		g_intr_cb();
	}

	sdio->card_intr = 0;

	return (ret);
}

void *sdio_event_handler(void *data)
{
	struct _pulse	pulse;
	iov_t			iov;
	int				rcvid;
	sdio_ext_t		*sdio = (sdio_ext_t *)data;

	// In case there is something has to be initialized in the event handler
	if (sdio->hdl_init)
		sdio->hdl_init(sdio->hchdl);

	SETIOV(&iov, &pulse, sizeof(pulse));

	while (1) {

		if ((rcvid = MsgReceivev(sdio->chid, &iov, 1, NULL)) == -1)
		{
			fprintf(stderr, "sdio_event_handler 2\r\n");
			continue;
		}

		switch (pulse.code) {
			case SDIO_PULSE:
				sdio_interrupt(sdio);
				InterruptUnmask(sdio->hc_irq, sdio->hc_iid);
				break;
			default:
				fprintf(stderr, "sdio_event_handler5\r\n");
				if (rcvid)
					MsgReplyv(rcvid, ENOTSUP, &iov, 1);
				break;
		}
	}

	return (NULL);
}


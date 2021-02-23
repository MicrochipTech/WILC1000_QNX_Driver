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

int sdio_send_command(void *hdl, sdio_cmd_t *cmd)
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	int			ret = SDIO_SUCCESS;

//	pthread_mutex_lock(&sdio->mutex);

	//slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[sdio_send_command] log0\n");
	if (cmd->eflags & (SDMMC_CMD_INTR | SDMMC_CMD_DATA)) {
		sdio->cmd = cmd;
		sdio->wait_cmd = 1;

		if (sdio->command(sdio->hchdl, cmd) != MMC_SUCCESS) {
			sdio->cmd = NULL;
			sdio->wait_cmd = 0;
			ret = SDIO_FAILURE;
			goto done;
		}


		// FIXME!!!
		// Data transfer might take long time, how long? 
		pthread_sleepon_lock();
		if (sdio->wait_cmd == 1) {
			if (pthread_sleepon_timedwait(&sdio->wait_cmd, 1000 * 1000 * 1000) != EOK)
			{
				printf("issue exist...\r\n");
				slogf(_SLOGC_NETWORK, _SLOG_ERROR,"sdio_send_command timeout...\n");
				ret = SDIO_FAILURE;
			}
			//sdio->command_done(sdio->hchdl, cmd);

		}

		sdio->cmd = NULL;
		sdio->wait_cmd = 0;
		pthread_sleepon_unlock();

		if (sdio->istatus & SDMMC_INT_ERROR){
			printf("[sdio_send_command] 0x%x failed\n", cmd->opcode);
			slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[sdio_send_command] 0x%x failed\n", cmd->opcode);
			//slogf(99,1,"%s 0x%x failed.", __FUNCTION__,cmd->opcode);
			ret = SDIO_FAILURE;
		}

	} else
	{

		ret = sdio->command(sdio->hchdl, cmd);
	}

	/*
	if (ret == SDIO_SUCCESS && sdio->command_done)
	{
		ret = sdio->command(sdio->hchdl, cmd);
	}
	*/
done:
//	pthread_mutex_unlock(&sdio->mutex);

	return (ret);
}


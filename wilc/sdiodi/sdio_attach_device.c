#include <sys/slog.h>

#include "proto.h"
static const unsigned char ena_func[8] = { 0, 0x02, 0x06, 0x0E, 0x1E, 0x3E, 0x7E, 0xFE };

static int sdio_enable_int(sdio_ext_t *sdio)
{
	uint8_t		reg;

	if (sdio_cmd52_write(sdio, SDIO_INT_ENABLE_REG, 0, ena_func[sdio->nfunc] | 0x01) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_INT_ENABLE_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	return (SDIO_SUCCESS);
}

static int sdio_enable_all(sdio_ext_t *sdio)
{
	uint8_t		reg;

	if (sdio_cmd52_write(sdio, SDIO_IO_ENABLE_REG, 0, ena_func[sdio->nfunc]) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_IO_ENABLE_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	return (SDIO_SUCCESS);
}
static int sdio_read_rca(sdio_ext_t *sdio, unsigned *rca)
{
	sdio_cmd_t	cmd;

	/* Send CMD5 with argument 0 */
	cmd.opcode  = MMC_SET_RELATIVE_ADDR;
	cmd.rsptype = MMC_RSP_R1;
	cmd.eflags  = SDMMC_CMD_INTR;
	cmd.argument = 0;
	if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
		return (SDIO_FAILURE);

	*rca = cmd.resp[0] >> 16;

	return (SDIO_SUCCESS);
}

static int sdio_select_card(sdio_ext_t *sdio, unsigned rca)
{
	sdio_cmd_t	cmd;

	/* Send CMD5 with argument 0 */
	cmd.opcode  = MMC_SEL_DES_CARD;
	cmd.rsptype = MMC_RSP_R1;
	cmd.eflags  = SDMMC_CMD_INTR;
	cmd.argument = rca << 16;
	if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS)
		return (SDIO_FAILURE);

	return (SDIO_SUCCESS);
}
static int sdio_write_ocr(sdio_ext_t *sdio, unsigned ocr)
{
	sdio_cmd_t	cmd;
	int			i;

	for (i = 0; i < 100; i++) {
		/* Send CMD5 with argument 0 */
		cmd.opcode  = IO_SEND_OP_COND;
		cmd.rsptype = SDIO_RSP_R4;
		cmd.eflags  = SDMMC_CMD_INTR;
		cmd.argument = ocr;
		if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS) {
			delay(10);
			continue;
		}
		if (cmd.resp[0] & 0x80000000)
			break;
	}

	if (i >= 100)
		return MMC_FAILURE;

	return (SDIO_SUCCESS);
}

static int sdio_read_ocr(sdio_ext_t *sdio, unsigned *ocr)
{
	sdio_cmd_t	cmd;
	int			i, j;

	for (j = 0; j < 5; j++) {
		for (i = 0; i < 100; i++) {
			/* Send CMD5 with argument 0 */
			cmd.opcode  = IO_SEND_OP_COND;
			cmd.rsptype = SDIO_RSP_R4;
			cmd.eflags  = SDMMC_CMD_INTR;
			cmd.argument = 0;
			if (sdio_send_command(sdio, &cmd) != MMC_SUCCESS) {
				delay(10);
				continue;
			}
			if (cmd.resp[0] & 0x80000000)
				break;
		}

		if (i >= 100)
			return MMC_FAILURE;

		if (cmd.resp[0] & 0x00FFFF00)
			break;
	}

	*ocr = cmd.resp[0];
	sdio->nfunc = (*ocr >> 28) & 0x07;

	return SDIO_SUCCESS;
}
int sdio_attach_device(void *hdl,int(*dev_attach)(void *sdio))
{
	sdio_ext_t	*sdio = (sdio_ext_t *)hdl;
	int			i, speed;
	unsigned	ocr, rca;
	uint8_t		reg, bw, buf[16];
	if(dev_attach){
		if(dev_attach(sdio) != SDIO_SUCCESS){
			printf("Customer device attach failed.\n");
			return SDIO_FAILURE;
		}
	}
	// TODO!!!
	// adjust power
	if (sdio->detect(sdio->hchdl) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	sdio->powerdown(sdio->hchdl);
	delay(50);
	sdio->powerup(sdio->hchdl);
	delay(100);
//	speed = 48000000;
//    if (sdio->bus_speed(sdio->hchdl, &speed) != MMC_SUCCESS)
//        printf("set bus speed fail\r\n");
//    printf("set bus speed to %d.\r\n",speed);
	if (sdio_read_ocr(sdio, &ocr) != SDIO_SUCCESS)
		goto fail;
	if (sdio_write_ocr(sdio, ocr & 0x00ffffff) != SDIO_SUCCESS)
		goto fail;

	if (sdio_read_rca(sdio, &rca) != SDIO_SUCCESS) {
		if (rca == 0) {
			if (sdio_read_rca(sdio, &rca) != SDIO_SUCCESS)
				goto fail;
			if (rca == 0)
				goto fail;
		}

	}

	if (sdio_select_card(sdio, rca) != SDIO_SUCCESS)
		goto fail;

	// FIXME!!!
	// enable all now?
	if (sdio_enable_all(sdio) != SDIO_SUCCESS)
		goto fail;

	if (sdio_enable_int(sdio) != SDIO_SUCCESS)
		goto fail;

	if (sdio_cmd52_read(sdio, SDIO_IO_READY_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_CARD_CAPABILITY_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;
	sdio->capability = reg;

	if (sdio_cmd52_read(sdio, SDIO_FUNCTION_SELECT_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_EXEC_FLAGS_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_READY_FLAGS_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_HIGH_SPEED_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;
	sdio->speed = reg;

	if (sdio->eflags & SDMMC_CAP_BW4)
		bw = 4;
	else
		bw = 1;

	// bus width
	if (sdio->capability & SDIO_CARD_CAP_LSC) {	// low speed
		speed = 400 * 1000;
		if (!(sdio->capability & SDIO_CARD_CAP_4BLS))
			bw = 1;
	} else if ((sdio->eflags & SDMMC_CAP_HS) && (sdio->speed & (1 << 0)))
		speed = 50 * 1000 * 1000;
	else
		speed = 25 * 1000 * 1000;

	reg = 0x80 | (bw >> 1);

	if (sdio_cmd52_write(sdio, SDIO_BUS_INTERFACE_CONTROL_REG, 0, reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

	if (sdio_cmd52_read(sdio, SDIO_BUS_INTERFACE_CONTROL_REG, 0, &reg) != SDIO_SUCCESS)
		return SDIO_FAILURE;

#if 0
	// TODO
	if ((sdio->speed & (1 << 0)) && (sdio->eflags & SDMMC_CAP_HS)) {
		if (sdio_cmd52_write(sdio, SDIO_HIGH_SPEED_REG, 0, 2) != SDIO_SUCCESS)
			return SDIO_FAILURE;
		if (sdio_cmd52_read(sdio, SDIO_HIGH_SPEED_REG, 0, &reg) != SDIO_SUCCESS)
			return SDIO_FAILURE;
		sdio->speed = reg;
		speed = (sdio->hclock < 50 * 1000 * 1000) ? sdio->hclock : 50 * 1000 * 1000;
	}
#endif

	// Read CIS pointer
	for (i = 0; i <= sdio->nfunc; i++) {
		if (sdio_cmd52_read(sdio, SDIO_FN_CIS_POINTER_0_REG(i), 0, &reg) != SDIO_SUCCESS)
			break;
		sdio->cisptr[i] = reg;
		if (sdio_cmd52_read(sdio, SDIO_FN_CIS_POINTER_1_REG(i), 0, &reg) != SDIO_SUCCESS)
			sdio->cisptr[i] = 0;
		else
			sdio->cisptr[i] |= reg << 8;
	}

	i = 256;
	if (sdio_read_cis(sdio, 0, SDIO_CISTPL_VERS_1, sdio->dev_name, &i) != SDIO_SUCCESS)
		goto fail;

	i = 4;
	if (sdio_read_cis(sdio, 0, SDIO_CISTPL_MANFID, buf, &i) != SDIO_SUCCESS)
		goto fail;

	if (i > 0) {
		sdio->dev_vid = (buf[1] << 8) | buf[0];
		sdio->dev_did = (buf[3] << 8) | buf[2];

		for (i = 0; i <= sdio->nfunc; i++) {
			sdio->func[i].vid = sdio->dev_vid;
			sdio->func[i].did = sdio->dev_did;
			sdio->func[i].ccd = 0;
			sdio->func[i].fun = i;

			if (i > 0) {
				if (sdio_cmd52_read(sdio, SDIO_FN_CSA_REG(i), 0, &reg) == SDIO_SUCCESS)
					sdio->func[i].ccd = reg;
			}
		}
	}

	if (sdio->bus_speed(sdio->hchdl, &speed) != MMC_SUCCESS)
		return SDIO_FAILURE;

	if (speed > 25000000) {
		if (sdio_cmd52_write(sdio, SDIO_HIGH_SPEED_REG, 0, reg | (1 << 1)) != SDIO_SUCCESS) {
			speed = 25000000;
			if (sdio->bus_speed(sdio->hchdl, &speed) != MMC_SUCCESS)
				return SDIO_FAILURE;
		}
	}

	if (sdio->bus_width(sdio->hchdl, bw) != MMC_SUCCESS)
		return SDIO_FAILURE;

	//if (sdio->dev_vid == vid && sdio->dev_did == did)
		return SDIO_SUCCESS;

fail:
	sdio->powerdown(sdio->hchdl);
	return SDIO_FAILURE;
}


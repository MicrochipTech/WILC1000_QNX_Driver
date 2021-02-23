// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef UNALIGNED_H
#define UNALIGNED_H

#include <inttypes.h>


static inline void put_unaligned_le16(uint16_t val, void *p)
{
	uint8_t *_p = p;
	_p[0] = val;
	_p[1] = val >> 8;
}

static inline void put_unaligned_le32(uint32_t val, void *p)
{
	uint8_t *_p = p;
	_p[0] = val;
	_p[1] = val >> 8;
	_p[2] = val >> 16;
	_p[3] = val >> 24;
}

#endif

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#ifndef TYPE_DEFS_H
#define TYPE_DEFS_H
#include <stdio.h>

#define u8	uint8_t
#define u16	uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s8	int8_t
#define s16	int16_t
#define s32	int32_t
#define __u8 uint8_t
#define __le16 uint16_t
#define __le32 uint32_t
#define __le64 uint64_t
#define __be16 uint16_t
#define __ble32 uint32_t
#define __be64 uint64_t


#define list_for_each_entry_rcu list_for_each_entry
#define list_del_rcu	list_del
#define spin_lock_irqsave(lock, flags)				\
	pthread_spin_lock(lock);

#define spin_unlock_irqrestore(lock, flags)				\
	pthread_spin_unlock(lock);

#define srcu_read_lock(srcu)	0
#define srcu_read_unlock(srcu, idx) (void)idx


#define cpu_to_le16
#define cpu_to_le32
//#define DEBUG

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#ifdef DEBUG
#define PRINT_INFO(region, format, ...) \
		slogf(_SLOGC_NETWORK, _SLOG_INFO, "[INFO] "format, ##__VA_ARGS__);
#else
#define PRINT_INFO(region, format, ...)
#endif

#ifdef DEBUG
#define PRINT_D(region, format, ...) \
		slogf(_SLOGC_NETWORK, _SLOG_INFO, "[DBG] "format, ##__VA_ARGS__);
#else
#define PRINT_D(region, format, ...)
#endif

#define PRINT_ER(netdev, format, ...) \
		slogf(_SLOGC_NETWORK, _SLOG_ERROR, "[ERROR] "format, ##__VA_ARGS__);

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof((arr)[0]))

#endif


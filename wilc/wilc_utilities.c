// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#include <sys/slogcodes.h>
#include <malloc.h>
#include "wilc_utilities.h"


void* create_ptr(size_t size)
{
	void *ptr;
	ptr = malloc(size);

	return ptr;
}

void free_ptr(void* ptr)
{
	free(ptr);
	return;
}

void kfree(void* ptr)
{
	free(ptr);
	return;
}

/*
 * $QNXLicenseC:
 * Copyright 2014, QNX Software Systems. 
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
 
#include <stdio.h>
#include <stdarg.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <pthread.h>

//static pthread_mutex_t logMutex = PTHREAD_RMUTEX_INITIALIZER;

int sdio_verbose = 9;			// -v for verbose operation

int
sdio_slogf(const int minVerbose, const char *fmt, ...)
{
    int         status = 0;
    va_list     arg;

	if( minVerbose <= sdio_verbose)
	{
		//pthread_mutex_lock( &logMutex);
		va_start(arg, fmt);
		status = vslogf(12, _SLOG_INFO, fmt, arg);
		va_end(arg);

		// If slogger not running, send output to stderr
		if( -1 == status)
		{
			va_start(arg, fmt);
			status = vfprintf(stderr, fmt, arg);
			va_end(arg);
		}
		//pthread_mutex_unlock( &logMutex);
	}
    return status;
}

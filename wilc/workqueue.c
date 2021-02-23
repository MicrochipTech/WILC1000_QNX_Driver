// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 - 2018 Microchip Technology Inc., and its subsidiaries.
 * All rights reserved.
 */

#include <mqueue.h>

#include <list.h>
#include <sys/slogcodes.h>
#include <sched.h>
#include <pthread.h>
#include "workqueue.h"
#include "wilc_utilities.h"
#include "type_defs.h"


struct workqueue_struct *test_wq = NULL;

void workqueue_handler(void *data)
{
	struct workqueue_struct *workqueue = (struct workqueue_struct *) data;
	struct work_struct *work;

	while (1)
	{

		///slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] workqueue = %p list = %p, next =%p\n", __func__, workqueue, &workqueue->list, workqueue->list.next);
		if (!list_empty(&workqueue->list))
		{
			PRINT_D(GENERIC_DBG, "[%s]  have data\n", __func__);
			work = list_first_entry(&workqueue->list, struct work_struct, entry);
			work->func(work);
			list_del(&work->entry);

		}
		usleep(10);

	}
}

struct workqueue_struct* create_singlethread_workqueue(char *queue_name)
{
	struct mq_attr q_attr;
	pthread_attr_t		t_attr;
	struct sched_param	sc_param;
	pthread_t tid;
	struct workqueue_struct* wq;

	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s] In\n", __func__);

	wq = create_ptr(sizeof (struct workqueue_struct));

	q_attr.mq_flags = 0;
	q_attr.mq_maxmsg = 10;
	q_attr.mq_msgsize = 256;
	q_attr.mq_curmsgs = 0;

	if ((wq->queue = mq_open(queue_name, O_CREAT | O_RDWR, 0644, &q_attr)) ==  -1)
	{
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s]  mq_open fail %d\n", __func__, errno);
	}


	INIT_LIST_HEAD(&wq->list);

	pthread_attr_init(&t_attr);
	pthread_attr_setschedpolicy(&t_attr, SCHED_RR);
	pthread_attr_setinheritsched(&t_attr, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&t_attr, 8192);

	/* Create SDIO event handler */
	if (pthread_create(&tid, &t_attr, (void *)workqueue_handler, wq)) {
		slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s]  Unable to create event pthread\n", __func__);
		return NULL;
	}

	int ret = pthread_getschedparam(tid, NULL, &sc_param );
	slogf(_SLOGC_NETWORK, _SLOG_ERROR,"[%s]  get priority = %d,  sched_curpriority = %d, ret = %d\n", __func__, sc_param.sched_priority, sc_param.sched_curpriority, ret);


	return wq;
}



int queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	list_add_tail(&work->entry,&wq->list);

	return 1;
}

void flush_workqueue(struct workqueue_struct *wq)
{
	// TODO
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	// TODO
}



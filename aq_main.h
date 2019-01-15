/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_main.h: Main file for aQuantia Linux driver. */

#ifndef AQ_MAIN_H
#define AQ_MAIN_H

#include "aq_common.h"
#include "aq_nic.h"

extern const char aq_ndev_driver_name[];

void aq_ndev_service_event_schedule(struct aq_nic_s *aq_nic);
struct net_device *aq_ndev_alloc(void);

#endif /* AQ_MAIN_H */

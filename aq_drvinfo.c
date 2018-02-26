/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_drvinfo.c: Definition of common code for firmware info in sys.*/

#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>

#include "aq_drvinfo.h"


static ssize_t show_temp(struct device *ndev, struct device_attribute *attr,
			    char *buf)
{
	int err;

	struct aq_nic_s *aq_nic = netdev_priv(to_net_dev(ndev));

	int temp = 0;

	if (!aq_nic->aq_fw_ops->get_temp)
		return -ENXIO;

	err = aq_nic->aq_fw_ops->get_temp(aq_nic->aq_hw, &temp);

	if (err == 0)
		return sprintf(buf, "%d.%d\n", temp / 100, temp % 100);
	return -ENXIO;
}


static ssize_t show_cable_len(struct device *ndev,
				struct device_attribute *attr, char *buf)
{
	int err;

	struct aq_nic_s *aq_nic = netdev_priv(to_net_dev(ndev));

	int cable_len = 0;

	if (!aq_nic->aq_fw_ops->get_cable_len)
		return -ENXIO;

	err = aq_nic->aq_fw_ops->get_cable_len(aq_nic->aq_hw, &cable_len);

	if (err == 0)
		return sprintf(buf, "%d\n", cable_len);
	return -ENXIO;
}


static struct device_attribute aq_dev_attrs[] = {
	__ATTR(temperature, 0444, show_temp, NULL),
	__ATTR(cable_length, 0444, show_cable_len, NULL),
};

int aq_sysfs_init(struct net_device *ndev)
{
	int i;
	int err = 0;

	for (i = 0; i < ARRAY_SIZE(aq_dev_attrs); i++) {
		err = device_create_file(&ndev->dev, &aq_dev_attrs[i]);
		if (err < 0) {
			while (i > 0)
				device_remove_file(&ndev->dev,
						&aq_dev_attrs[--i]);
			break;
		}
	}
	return err;
}

void aq_sysfs_exit(struct net_device *ndev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(aq_dev_attrs); i++)
		device_remove_file(&ndev->dev, &aq_dev_attrs[i]);
}


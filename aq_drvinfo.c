// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_drvinfo.c: Definition of common code for firmware info in sys.*/

#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "aq_drvinfo.h"
#include "aq_nic.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) && \
	IS_REACHABLE(CONFIG_HWMON)

static const char * const atl_temp_label[] = {
	"PHY Temperature",
	"MAC Temperature",
};

static ssize_t cable_show(struct device *ndev,
			  struct device_attribute *attr, char *buf)
{
	struct aq_nic_s *aq_nic = dev_get_drvdata(ndev);
	int cable_len = 0;
	int err;

	if (!aq_nic->aq_fw_ops->get_cable_len)
		return -ENXIO;

	mutex_lock(&aq_nic->fwreq_mutex);
	err = aq_nic->aq_fw_ops->get_cable_len(aq_nic->aq_hw, &cable_len);
	mutex_unlock(&aq_nic->fwreq_mutex);

	if (err == 0)
		return sprintf(buf, "%d\n", cable_len);
	return -ENXIO;
}

static ssize_t cable_label_show(struct device *ndev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "Estimated cable length (meters)\n");
}

static DEVICE_ATTR_RO(cable_label);
static SENSOR_DEVICE_ATTR(cable_input, 0444, cable_show, NULL, 1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static int aq_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
			 u32 attr, int channel, long *value)
{
	struct aq_nic_s *aq_nic = dev_get_drvdata(dev);
	int err = 0;
	int temp;

	if (!aq_nic)
		return -EIO;

	if (type != hwmon_temp || attr != hwmon_temp_input)
		return -EOPNOTSUPP;

	switch (channel) {
	case 0:
		if (!aq_nic->aq_fw_ops->get_phy_temp)
			return -EOPNOTSUPP;

		err = aq_nic->aq_fw_ops->get_phy_temp(aq_nic->aq_hw, &temp);
		*value = temp;
		break;
	case 1:
		if (!aq_nic->aq_fw_ops->get_mac_temp &&
		    !aq_nic->aq_hw_ops->hw_get_mac_temp)
			return -EOPNOTSUPP;

		if (aq_nic->aq_fw_ops->get_mac_temp)
			err = aq_nic->aq_fw_ops->get_mac_temp(aq_nic->aq_hw, &temp);
		else
			err = aq_nic->aq_hw_ops->hw_get_mac_temp(aq_nic->aq_hw, &temp);
		*value = temp;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return err;
}

static int aq_hwmon_read_string(struct device *dev,
				enum hwmon_sensor_types type,
				u32 attr, int channel, const char **str)
{
	struct aq_nic_s *aq_nic = dev_get_drvdata(dev);

	if (!aq_nic)
		return -EIO;

	if (type != hwmon_temp || attr != hwmon_temp_label)
		return -EOPNOTSUPP;

	if (channel < ARRAY_SIZE(atl_temp_label))
		*str = atl_temp_label[channel];
	else
		return -EOPNOTSUPP;

	return 0;
}

static umode_t aq_hwmon_is_visible(const void *data,
				   enum hwmon_sensor_types type,
				   u32 attr, int channel)
{
	const struct aq_nic_s *nic = data;

	if (type != hwmon_temp)
		return 0;

	if (channel == 0 && !nic->aq_fw_ops->get_phy_temp)
		return 0;
	else if (channel == 1 && !nic->aq_fw_ops->get_mac_temp &&
		 !nic->aq_hw_ops->hw_get_mac_temp)
		return 0;

	switch (attr) {
	case hwmon_temp_input:
	case hwmon_temp_label:
		return 0444;
	default:
		return 0;
	}
}

static const struct hwmon_ops aq_hwmon_ops = {
	.is_visible = aq_hwmon_is_visible,
	.read = aq_hwmon_read,
	.read_string = aq_hwmon_read_string,
};

static u32 aq_hwmon_temp_config[] = {
	HWMON_T_INPUT | HWMON_T_LABEL,
	HWMON_T_INPUT | HWMON_T_LABEL,
	0,
};

static const struct hwmon_channel_info aq_hwmon_temp = {
	.type = hwmon_temp,
	.config = aq_hwmon_temp_config,
};

static const struct hwmon_channel_info *aq_hwmon_info[] = {
	&aq_hwmon_temp,
	NULL,
};

static const struct hwmon_chip_info aq_hwmon_chip_info = {
	.ops = &aq_hwmon_ops,
	.info = aq_hwmon_info,
};

static struct attribute *aq_dev_attrs[] = {
	&dev_attr_cable_label.attr,
	&sensor_dev_attr_cable_input.dev_attr.attr,
	NULL
};

ATTRIBUTE_GROUPS(aq_dev);

int aq_drvinfo_init(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct device *dev = &aq_nic->pdev->dev;
	struct device *hwmon_dev;
	int err = 0;

	hwmon_dev = devm_hwmon_device_register_with_info(dev,
							 ndev->name,
							 aq_nic,
							 &aq_hwmon_chip_info,
							 aq_dev_groups);

	if (IS_ERR(hwmon_dev))
		err = PTR_ERR(hwmon_dev);

	return err;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static ssize_t temp1_input_show(struct device *ndev,
				struct device_attribute *attr, char *buf)
{
	struct aq_nic_s *aq_nic = dev_get_drvdata(ndev);
	int temp = 0;
	int err;

	if (!aq_nic->aq_fw_ops->get_phy_temp)
		return -ENXIO;
	mutex_lock(&aq_nic->fwreq_mutex);
	err = aq_nic->aq_fw_ops->get_phy_temp(aq_nic->aq_hw, &temp);
	mutex_unlock(&aq_nic->fwreq_mutex);

	if (err == 0)
		return sprintf(buf, "%d\n", temp);
	return -ENXIO;
}

static ssize_t temp1_label_show(struct device *ndev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", atl_temp_label[0]);
}

static DEVICE_ATTR_RO(temp1_label);
static SENSOR_DEVICE_ATTR(temp1_input, 0444, temp1_input_show, NULL, 0);
static struct attribute *aq_dev_attrs[] = {
	&dev_attr_temp1_label.attr,
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&dev_attr_cable_label.attr,
	&sensor_dev_attr_cable_input.dev_attr.attr,
	NULL
};

ATTRIBUTE_GROUPS(aq_dev);

int aq_drvinfo_init(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct pci_dev *pdev = aq_nic->pdev;
	struct device *dev = &pdev->dev;
	struct device *hwmon_dev;
	int err = 0;

	hwmon_dev = devm_hwmon_device_register_with_groups(&pdev->dev,
							   ndev->name,
							   dev_get_drvdata(&pdev->dev),
							   aq_dev_groups);

	if (IS_ERR(hwmon_dev))
		err = PTR_ERR(hwmon_dev);

	return err;
}
#endif /* LINUX_VERSION_CODE */
#else /* IS_REACHABLE(CONFIG_HWMON) */
int aq_drvinfo_init(struct net_device *ndev) { return 0; }
#endif

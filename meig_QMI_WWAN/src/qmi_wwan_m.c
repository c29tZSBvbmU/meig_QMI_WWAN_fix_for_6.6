/*
 * Copyright (c) 2012  Bjørn Mork <bjorn@mork.no>
 *
 * The probing code is heavily inspired by cdc_ether, which is:
 * Copyright (C) 2003-2005 by David Brownell
 * Copyright (C) 2006 by Ole Andre Vadla Ravnas (ActiveSync)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/usb/cdc.h>
#include <linux/usb/usbnet.h>
#include <linux/usb/cdc-wdm.h>
#include <linux/version.h>
#include <linux/pm.h>               /* MODIFIED FOR LINUX 6.6: add pm header for dev_pm_ops and PM helper macros */
#include <linux/kernel.h>           /* general kernel helpers */

/* This driver supports wwan (3G/LTE/?) devices using a vendor
 * specific management protocol called Qualcomm MSM Interface (QMI) - ... (omitted)
 */

/* User custom tx_fixup (kept) */
#if 1
//Added by zhangqingyun@meigsmart.com always need if not dhcp can't get ip address
struct sk_buff *qmi_wwan_tx_fixup(struct usbnet *dev, struct sk_buff *skb, gfp_t flags)
{
	if (dev->udev->descriptor.idVendor != cpu_to_le16(0x2C7C) &&
	    dev->udev->descriptor.idVendor != cpu_to_le16(0x05c6) &&
            dev->udev->descriptor.idVendor != cpu_to_le16(0x2dee)){
                // dev_err(&dev->intf->dev,"zhangqingyun test 1");
		return skb;
            }
	
	// Skip Ethernet header from message
	if (skb_pull(skb, ETH_HLEN)) {
                // dev_err(&dev->intf->dev, "zhangqingyu test 2");
		return skb;
	} else {
		dev_err(&dev->intf->dev, "Packet Dropped ");
	}

	// Filter the packet out, release it
	dev_kfree_skb_any(skb);
	return NULL;
}
#endif

#define VERSION_NUMBER "V1.0.1"
#define MEIG_WWAN_VERSION "Meig_QMI_WWAN_Driver_"VERSION_NUMBER

/* driver specific data */
struct qmi_wwan_state {
	struct usb_driver *subdriver;
	atomic_t pmcount;
	unsigned long unused;
	struct usb_interface *control;
	struct usb_interface *data;
};

/* default ethernet address used by the modem */
static const u8 default_modem_addr[ETH_ALEN] = {0x02, 0x50, 0xf3};

#define QUEC_NET_MSG_SPEC		(0x80)
#define QUEC_NET_MSG_ID_IP_DATA		(0x00)

struct quec_net_package_header {
	unsigned char msg_spec;
	unsigned char msg_id;
	unsigned short payload_len;
	unsigned char reserve[16];
} __packed;


static int qmi_wwan_rx_fixup(struct usbnet *dev, struct sk_buff *skb) {

	__be16 proto;

	/* this check is no longer done by usbnet (kept from original) */
	if (skb->len < dev->net->hard_header_len) {
		return 0;
	}


	switch (skb->data[0] & 0xf0) {
	case 0x40:
		proto = htons(ETH_P_IP);
		break;
	case 0x60:
		proto = htons(ETH_P_IPV6);
		break;
	case 0x00:
		if (is_multicast_ether_addr(skb->data)) {
			return 1;
		}
		skb_reset_mac_header(skb);
		goto fix_dest;

	default:
		return 1;
	}

	if (skb_headroom(skb) < ETH_HLEN) {
		return 0;
	}

	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	eth_hdr(skb)->h_proto = proto;
	memset(eth_hdr(skb)->h_source, 0, ETH_ALEN);
        /* add by zhangqingyun@meigsmart.com */
	memcpy(eth_hdr(skb)->h_source, "\x00\x11\x22\x33\x44\x55", ETH_ALEN);
fix_dest:
	memcpy(eth_hdr(skb)->h_dest, dev->net->dev_addr, ETH_ALEN);

	return 1;
}

/* very simplistic detection of IPv4 or IPv6 headers */
static bool possibly_iphdr(const char *data)
{
	return (data[0] & 0xd0) == 0x40;
}

/* disallow addresses which may be confused with IP headers */
static int qmi_wwan_mac_addr(struct net_device *dev, void *p)
{
	int ret;
	struct sockaddr *addr = p;

	ret = eth_prepare_mac_addr_change(dev, p);
	if (ret < 0)
		return ret;
	if (possibly_iphdr(addr->sa_data))
		return -EADDRNOTAVAIL;
	eth_commit_mac_addr_change(dev, p);
	return 0;
}

static const struct net_device_ops qmi_wwan_netdev_ops = {
	.ndo_open		= usbnet_open,
	.ndo_stop		= usbnet_stop,
	.ndo_start_xmit		= usbnet_start_xmit,
	.ndo_tx_timeout		= usbnet_tx_timeout,
	.ndo_change_mtu		= usbnet_change_mtu,
//	.ndo_get_stats64        = usbnet_get_stats64,
	.ndo_set_mac_address	= qmi_wwan_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

/* using a counter to merge subdriver requests with our own into a
 * combined state
 */
static int qmi_wwan_manage_power(struct usbnet *dev, int on)
{
	struct qmi_wwan_state *info = (void *)&dev->data;
	int rv;

	dev_dbg(&dev->intf->dev, "%s() pmcount=%d, on=%d\n", __func__,
		atomic_read(&info->pmcount), on);

	if ((on && atomic_add_return(1, &info->pmcount) == 1) ||
	    (!on && atomic_dec_and_test(&info->pmcount))) {
		/* need autopm_get/put here to ensure the usbcore sees
		 * the new value
		 */
		rv = usb_autopm_get_interface(dev->intf);
		dev->intf->needs_remote_wakeup = on;
		if (!rv)
			usb_autopm_put_interface(dev->intf);
	}
	return 0;
}

static int qmi_wwan_cdc_wdm_manage_power(struct usb_interface *intf, int on)
{
	struct usbnet *dev = usb_get_intfdata(intf);

	/* can be called while disconnecting */
	if (!dev)
		return 0;
	return qmi_wwan_manage_power(dev, on);
}

/* collect all three endpoints and register subdriver */
static int qmi_wwan_register_subdriver(struct usbnet *dev)
{
	int rv;
	struct usb_driver *subdriver = NULL;
	struct qmi_wwan_state *info = (void *)&dev->data;

	/* collect bulk endpoints */
	rv = usbnet_get_endpoints(dev, info->data);
	if (rv < 0)
		goto err;

	/* update status endpoint if separate control interface */
	if (info->control != info->data)
		dev->status = &info->control->cur_altsetting->endpoint[0];

	/* require interrupt endpoint for subdriver */
	if (!dev->status) {
		rv = -EINVAL;
		goto err;
	}

	/* for subdriver power management */
	atomic_set(&info->pmcount, 0);

	/* register subdriver */
	subdriver = usb_cdc_wdm_register(info->control, &dev->status->desc,
					 4096, &qmi_wwan_cdc_wdm_manage_power);
	if (IS_ERR(subdriver)) {
		dev_err(&info->control->dev, "subdriver registration failed\n");
		rv = PTR_ERR(subdriver);
		goto err;
	}

	/* prevent usbnet from using status endpoint */
	dev->status = NULL;

	/* save subdriver struct for suspend/resume wrappers */
	info->subdriver = subdriver;

err:
	return rv;
}

static int qmi_wwan_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int status = -1;
	u8 *buf = intf->cur_altsetting->extra;
	int len = intf->cur_altsetting->extralen;
	struct usb_interface_descriptor *desc = &intf->cur_altsetting->desc;
	struct usb_cdc_union_desc *cdc_union = NULL;
	struct usb_cdc_ether_desc *cdc_ether = NULL;
	u32 found = 0;
	struct usb_driver *driver = driver_of(intf);
	struct qmi_wwan_state *info = (void *)&dev->data;

	BUILD_BUG_ON((sizeof(((struct usbnet *)0)->data) <
		      sizeof(struct qmi_wwan_state)));

	/* set up initial state */
	info->control = intf;
	info->data = intf;
        /*add by zhangqingyun@meigsmart.com begain
	/* and a number of CDC descriptors */
	while (len > 3) {
		struct usb_descriptor_header *h = (void *)buf;

		/* ignore any misplaced descriptors */
		if (h->bDescriptorType != USB_DT_CS_INTERFACE)
			goto next_desc;

		/* buf[2] is CDC descriptor subtype */
		switch (buf[2]) {
		case USB_CDC_HEADER_TYPE:
			if (found & 1 << USB_CDC_HEADER_TYPE) {
				dev_dbg(&intf->dev, "extra CDC header\n");
				goto err;
			}
			if (h->bLength != sizeof(struct usb_cdc_header_desc)) {
				dev_dbg(&intf->dev, "CDC header len %u\n",
					h->bLength);
				goto err;
			}
			break;
		case USB_CDC_UNION_TYPE:
			if (found & 1 << USB_CDC_UNION_TYPE) {
				dev_dbg(&intf->dev, "extra CDC union\n");
				goto err;
			}
			if (h->bLength != sizeof(struct usb_cdc_union_desc)) {
				dev_dbg(&intf->dev, "CDC union len %u\n",
					h->bLength);
				goto err;
			}
			cdc_union = (struct usb_cdc_union_desc *)buf;
			break;
		case USB_CDC_ETHERNET_TYPE:
			if (found & 1 << USB_CDC_ETHERNET_TYPE) {
				dev_dbg(&intf->dev, "extra CDC ether\n");
				goto err;
			}
			if (h->bLength != sizeof(struct usb_cdc_ether_desc)) {
				dev_dbg(&intf->dev, "CDC ether len %u\n",
					h->bLength);
				goto err;
			}
			cdc_ether = (struct usb_cdc_ether_desc *)buf;
			break;
		}

		/* Remember which CDC functional descriptors we've seen.  Works
		 * for all types we care about, of which USB_CDC_ETHERNET_TYPE
		 * (0x0f) is the highest numbered
		 */
		if (buf[2] < 32)
			found |= 1 << buf[2];

next_desc:
		len -= h->bLength;
		buf += h->bLength;
	}
        /*add by zhangqingyun@meigsmart.com end*/
	/* Use separate control and data interfaces if we found a CDC Union */
	if (cdc_union) {
		info->data = usb_ifnum_to_if(dev->udev,
					     cdc_union->bSlaveInterface0);
		if (desc->bInterfaceNumber != cdc_union->bMasterInterface0 ||
		    !info->data) {
			dev_err(&intf->dev,
				"bogus CDC Union: master=%u, slave=%u\n",
				cdc_union->bMasterInterface0,
				cdc_union->bSlaveInterface0);
			goto err;
		}
	}

	/* errors aren't fatal - we can live with the dynamic address */
	if (cdc_ether) {
		dev->hard_mtu = le16_to_cpu(cdc_ether->wMaxSegmentSize);
		usbnet_get_ethernet_addr(dev, cdc_ether->iMACAddress);
	}

	/* claim data interface and set it up */
	if (info->control != info->data) {
		status = usb_driver_claim_interface(driver, info->data, dev);
		if (status < 0)
			goto err;
	}

	status = qmi_wwan_register_subdriver(dev);
	if (status < 0 && info->control != info->data) {
		usb_set_intfdata(info->data, NULL);
		usb_driver_release_interface(driver, info->data);
	}

	/* Never use the same address on both ends of the link, even
	 * if the buggy firmware told us to.
	 */
	if (ether_addr_equal(dev->net->dev_addr, default_modem_addr))
		eth_hw_addr_random(dev->net);

	/* make MAC addr easily distinguishable from an IP header */
	if (possibly_iphdr(dev->net->dev_addr)) {
		dev->net->dev_addr[0] |= 0x02;	/* set local assignment bit */
		dev->net->dev_addr[0] &= 0xbf;	/* clear "IP" bit */
	}
	dev->net->netdev_ops = &qmi_wwan_netdev_ops;

	//dev->rx_urb_size = 7600;

#if 1 //Added by zhangqingyun@meigsmart.com
	if (dev->udev->descriptor.idVendor == cpu_to_le16(0x2C7C) ||
	    dev->udev->descriptor.idVendor == cpu_to_le16(0x05c6) ||
            dev->udev->descriptor.idVendor == cpu_to_le16(0x2dee)) {
		dev_info(&intf->dev, "MeigSmart slm750 slm730 srm815 work on RawIP mode\n");
		dev->net->flags |= IFF_NOARP;
	/* make MAC addr easily distinguishable from an IP header */
	usb_control_msg(interface_to_usbdev(intf),
				usb_sndctrlpipe(interface_to_usbdev(intf), 0),
				0x22, //USB_CDC_REQ_SET_CONTROL_LINE_STATE
				0x21, //USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE
				1, //active CDC DTR
				intf->cur_altsetting->desc.bInterfaceNumber,
				NULL, 0, 100);
	}
#endif

err:
	return status;
}

static void qmi_wwan_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	struct qmi_wwan_state *info = (void *)&dev->data;
	struct usb_driver *driver = driver_of(intf);
	struct usb_interface *other;

	if (info->subdriver && info->subdriver->disconnect)
		info->subdriver->disconnect(info->control);

	/* allow user to unbind using either control or data */
	if (intf == info->control)
		other = info->data;
	else
		other = info->control;

	/* only if not shared */
	if (other && intf != other) {
		usb_set_intfdata(other, NULL);
		usb_driver_release_interface(driver, other);
	}

	info->subdriver = NULL;
	info->data = NULL;
	info->control = NULL;
}

/* ------------------------------------------------------------------
 * SUSPEND / RESUME
 *
 * Original code used usb_driver .suspend/.resume with pm_message_t.
 * For better compatibility with newer kernels (>=5.x/6.x) use dev_pm_ops
 * and provide device -> usb_interface wrappers to call existing
 * usb-interface based suspend/resume helpers.
 *
 * We keep the original qmi_wwan_suspend and qmi_wwan_resume (usb-interface
 * based) so behavior remains the same; but register wrapper functions
 * for the dev_pm_ops table which convert device -> usb_interface and
 * call the original routines.
 */

/* Original suspend/resume kept (signature with pm_message_t) */
static int qmi_wwan_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct qmi_wwan_state *info = (void *)&dev->data;
	int ret;

	/* Both usbnet_suspend() and subdriver->suspend() MUST return 0
	 * in system sleep context, otherwise, the resume callback has
	 * to recover device from previous suspend failure.
	 */
	ret = usbnet_suspend(intf, message);
	if (ret < 0)
		goto err;

	if (intf == info->control && info->subdriver &&
	    info->subdriver->suspend)
		ret = info->subdriver->suspend(intf, message);
	if (ret < 0)
		usbnet_resume(intf);
err:
	return ret;
}

static int qmi_wwan_resume(struct usb_interface *intf)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct qmi_wwan_state *info = (void *)&dev->data;
	int ret = 0;
	bool callsub = (intf == info->control && info->subdriver &&
			info->subdriver->resume);

	if (callsub)
		ret = info->subdriver->resume(intf);
	if (ret < 0)
		goto err;
	ret = usbnet_resume(intf);
	if (ret < 0 && callsub)
		info->subdriver->suspend(intf, PMSG_SUSPEND);
err:
	return ret;
}

/* MODIFIED FOR LINUX 6.6:
 * wrapper functions for dev_pm_ops (the PM core passes struct device *)
 * Convert device -> usb_interface, then call original usb-interface
 * based suspend/resume.
 */
static int qmi_wwan_pm_suspend(struct device *dev)
{
	struct usb_interface *intf = to_usb_interface(dev);
	/* Convert to system sleep pm_message */
	return qmi_wwan_suspend(intf, PMSG_SUSPEND);
}

static int qmi_wwan_pm_resume(struct device *dev)
{
	struct usb_interface *intf = to_usb_interface(dev);
	return qmi_wwan_resume(intf);
}

/* Provide dev_pm_ops so kernel 6.x uses recommended PM hooks */
static const struct dev_pm_ops qmi_wwan_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(qmi_wwan_pm_suspend, qmi_wwan_pm_resume),
	/* runtime PM could be added if desired */
};

/* ------------------------------------------------------------------ */

static const struct driver_info	qmi_wwan_info = {
	.description	= "WWAN/QMI device",
	.flags		= FLAG_WWAN | FLAG_SEND_ZLP,
	.bind		= qmi_wwan_bind,
	.unbind		= qmi_wwan_unbind,
	.manage_power	= qmi_wwan_manage_power,
	.rx_fixup       = qmi_wwan_rx_fixup,
#if 1 //Added by zhangqingyun@meigsmart.com
	.tx_fixup = qmi_wwan_tx_fixup,
#endif
};

#define HUAWEI_VENDOR_ID	0x12D1

/* map QMI/wwan function by a fixed interface number */
#define QMI_FIXED_INTF(vend, prod, num) \
	USB_DEVICE_INTERFACE_NUMBER(vend, prod, num), \
	.driver_info = (unsigned long)&qmi_wwan_info

/* Gobi 1000 QMI/wwan interface number is 3 according to qcserial */
#define QMI_GOBI1K_DEVICE(vend, prod) \
	QMI_FIXED_INTF(vend, prod, 3)

/* Gobi 2000/3000 QMI/wwan interface number is 0 according to qcserial */
#define QMI_GOBI_DEVICE(vend, prod) \
	QMI_FIXED_INTF(vend, prod, 0)

static const struct usb_device_id products[] = {
#if 1 //Added by Quectel
#ifndef QMI_FIXED_INTF
/* map QMI/wwan function by a fixed interface number */
#define QMI_FIXED_INTF(vend, prod, num) \
		.match_flags = USB_DEVICE_ID_MATCH_DEVICE | USB_DEVICE_ID_MATCH_INT_INFO, \
		.idVendor = vend, \
		.idProduct = prod, \
		.bInterfaceClass = 0xff, \
		.bInterfaceSubClass = 0xff, \
		.bInterfaceProtocol = 0xff, \
		.driver_info = (unsigned long)&qmi_wwan_force_int##num,
#endif
	{ QMI_FIXED_INTF(0x2C7C, 0x0125, 4) }, /* Quectel EC25/EC20 R2.0 */
	{ QMI_FIXED_INTF(0x2C7C, 0x0121, 4) }, /* Quectel EC21 */
	{ QMI_FIXED_INTF(0x05c6, 0xf601, 5) }, /* MeigLink SLM750 SLM730 SLM750VR2.0*/
        { QMI_FIXED_INTF(0x2dee, 0x4d22, 5) }, /*MeigLink SRM815*/
#endif
	/* 1. CDC ECM like devices match on the control interface */
	{	/* Huawei E392, E398 and possibly others sharing both device id and more... */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 9),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Vodafone/Huawei K5005 (12d1:14c8) and similar modems */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 57),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* HUAWEI_INTERFACE_NDIS_CONTROL_QUALCOMM */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 0x01, 0x69),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},

	/* 2. Combined interface devices matching on class+protocol */
	{	/* Huawei E367 and possibly others in "Windows mode" */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 7),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Huawei E392, E398 and possibly others in "Windows mode" */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 17),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* HUAWEI_NDIS_SINGLE_INTERFACE_VDF */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 0x01, 0x37),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* HUAWEI_INTERFACE_NDIS_HW_QUALCOMM */
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 0x01, 0x67),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Pantech UML290, P4200 and more */
		USB_VENDOR_AND_INTERFACE_INFO(0x106c, USB_CLASS_VENDOR_SPEC, 0xf0, 0xff),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Pantech UML290 - newer firmware */
		USB_VENDOR_AND_INTERFACE_INFO(0x106c, USB_CLASS_VENDOR_SPEC, 0xf1, 0xff),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Novatel USB551L and MC551 */
		USB_DEVICE_AND_INTERFACE_INFO(0x1410, 0xb001,
		                              USB_CLASS_COMM,
		                              USB_CDC_SUBCLASS_ETHERNET,
		                              USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Novatel E362 */
		USB_DEVICE_AND_INTERFACE_INFO(0x1410, 0x9010,
		                              USB_CLASS_COMM,
		                              USB_CDC_SUBCLASS_ETHERNET,
		                              USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Novatel Expedite E371 */
		USB_DEVICE_AND_INTERFACE_INFO(0x1410, 0x9011,
		                              USB_CLASS_COMM,
		                              USB_CDC_SUBCLASS_ETHERNET,
		                              USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Dell Wireless 5800 (Novatel E362) */
		USB_DEVICE_AND_INTERFACE_INFO(0x413C, 0x8195,
					      USB_CLASS_COMM,
					      USB_CDC_SUBCLASS_ETHERNET,
					      USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Dell Wireless 5800 V2 (Novatel E362) */
		USB_DEVICE_AND_INTERFACE_INFO(0x413C, 0x8196,
					      USB_CLASS_COMM,
					      USB_CDC_SUBCLASS_ETHERNET,
					      USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* Dell Wireless 5804 (Novatel E371) */
		USB_DEVICE_AND_INTERFACE_INFO(0x413C, 0x819b,
					      USB_CLASS_COMM,
					      USB_CDC_SUBCLASS_ETHERNET,
					      USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* ADU960S */
		USB_DEVICE_AND_INTERFACE_INFO(0x16d5, 0x650a,
					      USB_CLASS_COMM,
					      USB_CDC_SUBCLASS_ETHERNET,
					      USB_CDC_PROTO_NONE),
		.driver_info        = (unsigned long)&qmi_wwan_info,
	},
	{	/* HP lt4112 LTE/HSPA+ Gobi 4G Module (Huawei me906e) */
		USB_DEVICE_AND_INTERFACE_INFO(0x03f0, 0x581d, USB_CLASS_VENDOR_SPEC, 1, 7),
		.driver_info = (unsigned long)&qmi_wwan_info,
	},

	/* 3. Combined interface devices matching on interface number */
	{QMI_FIXED_INTF(0x0408, 0xea42, 4)},	/* Yota / Megafon M100-1 */
	{QMI_FIXED_INTF(0x05c6, 0x7000, 0)},
	{QMI_FIXED_INTF(0x05c6, 0x7001, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7002, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7101, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7101, 2)},

	{ }					/* END */
};
MODULE_DEVICE_TABLE(usb, products);

/* zhangqingyun add pid+vid+interfacenumber determine is ndis port or not */
static bool ndis_detected(struct usb_interface *intf)
{
	struct usb_device *dev = interface_to_usbdev(intf);

	if (dev->actconfig &&
	    le16_to_cpu(dev->descriptor.idVendor) == 0x05c6 &&
	    le16_to_cpu(dev->descriptor.idProduct) == 0x9215 &&
	    dev->actconfig->desc.bNumInterfaces == 5) {
		return true;
	}
    /*zhangqingyun add start */
	if (dev->actconfig &&
	    le16_to_cpu(dev->descriptor.idVendor) == 0x05c6 &&
	    le16_to_cpu(dev->descriptor.idProduct) == 0xf601 &&
	    dev->actconfig->desc.bNumInterfaces == 5) {
		dev_dbg(&intf->dev, "zhangqingyun detemine interface 5 is ndis port");
		return true;
	}
        if (dev->actconfig && 
            le16_to_cpu(dev->descriptor.idVendor) == 0x2dee &&
            le16_to_cpu(dev->descriptor.idProduct) == 0x4d22 &&
            dev->actconfig->desc.bNumInterfaces == 5){
                dev_dbg(&intf->dev, "zhangqingyun detemine interface 5 is ndis port");
                return true;
        }
	/*zhangqingyun add end*/
	return false;
}

static int qmi_wwan_probe(struct usb_interface *intf,
			  const struct usb_device_id *prod)
{
	struct usb_device_id *id = (struct usb_device_id *)prod;
	struct usb_interface_descriptor *desc = &intf->cur_altsetting->desc;

	/* Workaround to enable dynamic IDs.  This disables usbnet
	 * blacklisting functionality.  Which, if required, can be
	 * reimplemented here by using a magic "blacklist" value
	 * instead of 0 in the static device id table
	 */
	if (!id->driver_info) {
		dev_dbg(&intf->dev, "setting defaults for dynamic device id\n");
		id->driver_info = (unsigned long)&qmi_wwan_info;
	}

	/* where we've QMI on interface 5 instead of 0 */
	if (ndis_detected(intf) && desc->bInterfaceNumber == 0) {
		dev_dbg(&intf->dev, "skipping interface 0\n");
		return -ENODEV;
	}

	return usbnet_probe(intf, id);
}

/* MODIFIED FOR LINUX 6.6:
 * Use modern .driver.pm = &qmi_wwan_pm_ops and do not rely on
 * .suspend/.resume fields in the top-level usb_driver structure.
 * This avoids oddities if kernel expects dev_pm_ops.
 */
static struct usb_driver qmi_wwan_driver = {
	.name		      = "qmi_wwan_m",
	.id_table	      = products,
	.probe		      = qmi_wwan_probe,
	.disconnect	      = usbnet_disconnect,
	/* .suspend and .resume are handled through dev_pm_ops wrapper */
	.supports_autosuspend = 1,
	.disable_hub_initiated_lpm = 1,
	.driver = {
		.name = "qmi_wwan_m",
		.pm = &qmi_wwan_pm_ops, /* MODIFIED FOR LINUX 6.6: register pm ops here */
	},
};

module_usb_driver(qmi_wwan_driver);

MODULE_AUTHOR("Bjørn Mork <bjorn@mork.no>");
MODULE_DESCRIPTION("Qualcomm MSM Interface (QMI) WWAN driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(MEIG_WWAN_VERSION);

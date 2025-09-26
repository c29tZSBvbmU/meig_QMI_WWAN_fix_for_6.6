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

#include <linux/module.h>            // 包含模块定义头文件
#include <linux/netdevice.h>         // 包含网络设备头文件
#include <linux/ethtool.h>           // 包含ethtool头文件
#include <linux/etherdevice.h>       // 包含以太网设备头文件
#include <linux/mii.h>               // 包含MII头文件
#include <linux/usb.h>               // 包含USB头文件
#include <linux/usb/cdc.h>           // 包含USB CDC头文件
#include <linux/usb/usbnet.h>        // 包含USB网络头文件
#include <linux/usb/cdc-wdm.h>       // 包含USB CDC WDM头文件
#include <linux/version.h>           // 包含内核版本头文件

/* This driver supports wwan (3G/LTE/?) devices using a vendor
 * specific management protocol called Qualcomm MSM Interface (QMI) -
 * in addition to the more common AT commands over serial interface
 * management
 *
 * QMI is wrapped in CDC, using CDC encapsulated commands on the
 * control ("master") interface of a two-interface CDC Union
 * resembling standard CDC ECM.  The devices do not use the control
 * interface for any other CDC messages.  Most likely because the
 * management protocol is used in place of the standard CDC
 * notifications NOTIFY_NETWORK_CONNECTION and NOTIFY_SPEED_CHANGE
 *
 * Alternatively, control and data functions can be combined in a
 * single USB interface.
 *
 * Handling a protocol like QMI is out of the scope for any driver.
 * It is exported as a character device using the cdc-wdm driver as
 * a subdriver, enabling userspace applications ("modem managers") to
 * handle it.
 *
 * These devices may alternatively/additionally be configured using AT
 * commands on a serial interface
 */
 
 #if 1
//Added by zhangqingyun@meigsmart.com always need if not dhcp can't get ip address
struct sk_buff *qmi_wwan_tx_fixup(struct usbnet *dev, struct sk_buff *skb, gfp_t flags) // 定义发送数据包修复函数
{
	if (dev->udev->descriptor.idVendor != cpu_to_le16(0x2C7C) && // 检查供应商ID是否不等于0x2C7C
	    dev->udev->descriptor.idVendor != cpu_to_le16(0x05c6) && // 检查供应商ID是否不等于0x05c6
            dev->udev->descriptor.idVendor != cpu_to_le16(0x2dee)){ // 检查供应商ID是否不等于0x2dee
                // dev_err(&dev->intf->dev,"zhangqingyun test 1");
		return skb; // 如果供应商ID不匹配，直接返回原始skb
            }
	
	// Skip Ethernet header from message // 跳过消息中的以太网头部
	if (skb_pull(skb, ETH_HLEN)) { // 尝试移除ETH_HLEN字节的头部
                // dev_err(&dev->intf->dev, "zhangqingyu test 2");
		return skb; // 如果移除成功，返回修改后的skb
	} else {
		dev_err(&dev->intf->dev, "Packet Dropped "); // 如果移除失败，记录错误信息
	}

	// Filter the packet out, release it // 过滤并释放数据包
	dev_kfree_skb_any(skb); // 释放数据包
	return NULL; // 返回空指针
}
#endif
#include <linux/version.h> // 再次包含内核版本头文件

#define VERSION_NUMBER "V1.0.1" // 定义驱动版本号
#define MEIG_WWAN_VERSION "Meig_QMI_WWAN_Driver_"VERSION_NUMBER // 定义带版本号的驱动版本字符串

/* driver specific data */ // 驱动特定数据结构
struct qmi_wwan_state { // 定义QMI WWAN状态结构体
	struct usb_driver *subdriver; // 子驱动指针
	atomic_t pmcount; // 原子计数器，用于电源管理
	unsigned long unused; // 未使用的字段
	struct usb_interface *control; // 控制接口指针
	struct usb_interface *data; // 数据接口指针
};

/* default ethernet address used by the modem */ // 调制解调器使用的默认以太网地址
static const u8 default_modem_addr[ETH_ALEN] = {0x02, 0x50, 0xf3}; // 初始化默认MAC地址

#define QUEC_NET_MSG_SPEC		(0x80) // 定义网络消息规格常量

#define QUEC_NET_MSG_ID_IP_DATA		(0x00) // 定义IP数据消息ID常量

struct quec_net_package_header { // 定义网络包头部结构
	unsigned char msg_spec; // 消息规格
	unsigned char msg_id; // 消息ID
	unsigned short payload_len; // 有效载荷长度
	unsigned char reserve[16]; // 预留字段
} __packed; // 紧凑打包结构体


static int qmi_wwan_rx_fixup(struct usbnet *dev, struct sk_buff *skb) { // 定义接收数据包修复函数

	__be16 proto; // 定义网络协议类型变量

	//this check is no longer done by usbnet // 此检查不再由usbnet执行
	if (skb->len < dev->net->hard_header_len) { // 检查数据包长度是否小于硬件头部长度
		return 0; // 如果小于，返回0（失败）
	}


	switch (skb->data[0] & 0xf0) { // 根据数据的第一个字节的高4位判断协议类型
	case 0x40: // IPv4
		proto = htons(ETH_P_IP); // 设置协议类型为IPv4
		break;
	case 0x60: // IPv6
		proto = htons(ETH_P_IPV6); // 设置协议类型为IPv6
		break;
	case 0x00: // 0x00开头的数据
		if (is_multicast_ether_addr(skb->data)) { // 检查是否为多播以太网地址
			return 1; // 是多播地址，返回1（成功）
		}
		skb_reset_mac_header(skb); // 重置MAC头部
		goto fix_dest; // 跳转到fix_dest标签

	default: // 其他情况
		return 1; // 返回1（成功）
	}

	if (skb_headroom(skb) < ETH_HLEN) { // 检查skb头部空间是否小于ETH_HLEN
		return 0; // 如果不足，返回0（失败）
	}

	skb_push(skb, ETH_HLEN); // 在skb数据区前推入ETH_HLEN个字节的空间
	skb_reset_mac_header(skb); // 重置MAC头部
	eth_hdr(skb)->h_proto = proto; // 设置以太网头部的协议类型
	memset(eth_hdr(skb)->h_source, 0, ETH_ALEN); // 将源MAC地址清零
        //add by zhangqingyun@meigsmart.com // 添加zhangqingyun的修改
	memcpy(eth_hdr(skb)->h_source, "\x00\x11\x22\x33\x44\x55", ETH_ALEN); // 复制新的源MAC地址
fix_dest: // 标签fix_dest
	memcpy(eth_hdr(skb)->h_dest, dev->net->dev_addr, ETH_ALEN); // 复制目标MAC地址

	return 1; // 返回1（成功）
}

/* very simplistic detection of IPv4 or IPv6 headers */ // 简单检测IPv4或IPv6头部
static bool possibly_iphdr(const char *data) // 定义检测IP头部的函数
{
	return (data[0] & 0xd0) == 0x40; // 检查第一个字节的高4位是否为0x40或0x60
}

/* disallow addresses which may be confused with IP headers */ // 不允许可能与IP头部混淆的地址
static int qmi_wwan_mac_addr(struct net_device *dev, void *p) // 定义设置MAC地址的函数
{
	int ret; // 定义返回值变量
	struct sockaddr *addr = p; // 将void指针转换为sockaddr指针

	ret = eth_prepare_mac_addr_change(dev, p); // 准备MAC地址更改
	if (ret < 0) // 如果准备失败
		return ret; // 返回错误码
	if (possibly_iphdr(addr->sa_data)) // 如果新地址可能被误认为IP头部
		return -EADDRNOTAVAIL; // 返回地址不可用错误
	eth_commit_mac_addr_change(dev, p); // 提交MAC地址更改
	return 0; // 返回成功
}

static const struct net_device_ops qmi_wwan_netdev_ops = { // 定义网络设备操作结构体
	.ndo_open		= usbnet_open, // 打开网络设备
	.ndo_stop		= usbnet_stop, // 停止网络设备
	.ndo_start_xmit		= usbnet_start_xmit, // 开始传输数据
	.ndo_tx_timeout		= usbnet_tx_timeout, // 发送超时处理
	.ndo_change_mtu		= usbnet_change_mtu, // 更改MTU
	.ndo_get_stats64        = usbnet_get_stats64, // 获取统计信息
	.ndo_set_mac_address	= qmi_wwan_mac_addr, // 设置MAC地址
	.ndo_validate_addr	= eth_validate_addr, // 验证MAC地址
};

/* using a counter to merge subdriver requests with our own into a
 * combined state
 */
static int qmi_wwan_manage_power(struct usbnet *dev, int on) // 定义电源管理函数
{
	struct qmi_wwan_state *info = (void *)&dev->data; // 获取QMI WWAN状态信息
	int rv; // 定义返回值变量

	dev_dbg(&dev->intf->dev, "%s() pmcount=%d, on=%d\n", __func__, // 打印调试信息
		atomic_read(&info->pmcount), on);

	if ((on && atomic_add_return(1, &info->pmcount) == 1) || // 如果开启且计数器变为1，或关闭且计数器变为0
	    (!on && atomic_dec_and_test(&info->pmcount))) {
		/* need autopm_get/put here to ensure the usbcore sees
		 * the new value
		 */
		rv = usb_autopm_get_interface(dev->intf); // 获取USB接口的自动电源管理
		dev->intf->needs_remote_wakeup = on; // 设置是否需要远程唤醒
		if (!rv) // 如果获取成功
			usb_autopm_put_interface(dev->intf); // 释放USB接口的自动电源管理
	}
	return 0; // 返回成功
}

static int qmi_wwan_cdc_wdm_manage_power(struct usb_interface *intf, int on) // 定义CDC WDM电源管理函数
{
	struct usbnet *dev = usb_get_intfdata(intf); // 获取USB接口关联的usbnet设备

	/* can be called while disconnecting */ // 可能在断开连接时调用
	if (!dev) // 如果设备为空
		return 0; // 直接返回成功
	return qmi_wwan_manage_power(dev, on); // 调用通用电源管理函数
}

/* collect all three endpoints and register subdriver */ // 收集所有端点并注册子驱动
static int qmi_wwan_register_subdriver(struct usbnet *dev) // 定义注册子驱动函数
{
	int rv; // 定义返回值变量
	struct usb_driver *subdriver = NULL; // 定义子驱动指针
	struct qmi_wwan_state *info = (void *)&dev->data; // 获取QMI WWAN状态信息

	/* collect bulk endpoints */ // 收集批量传输端点
	rv = usbnet_get_endpoints(dev, info->data); // 获取数据接口的端点
	if (rv < 0) // 如果获取失败
		goto err; // 跳转到错误处理

	/* update status endpoint if separate control interface */ // 如果控制接口是独立的，更新状态端点
	if (info->control != info->data) // 如果控制接口不等于数据接口
		dev->status = &info->control->cur_altsetting->endpoint[0]; // 设置状态端点

	/* require interrupt endpoint for subdriver */ // 子驱动需要中断端点
	if (!dev->status) { // 如果状态端点为空
		rv = -EINVAL; // 设置错误码为无效参数
		goto err; // 跳转到错误处理
	}

	/* for subdriver power management */ // 为子驱动电源管理
	atomic_set(&info->pmcount, 0); // 初始化电源管理计数器为0

	/* register subdriver */ // 注册子驱动
	subdriver = usb_cdc_wdm_register(info->control, &dev->status->desc, // 注册CDC WDM子驱动
					 4096, &qmi_wwan_cdc_wdm_manage_power);
	if (IS_ERR(subdriver)) { // 如果注册失败
		dev_err(&info->control->dev, "subdriver registration failed\n"); // 打印错误信息
		rv = PTR_ERR(subdriver); // 获取错误码
		goto err; // 跳转到错误处理
	}

	/* prevent usbnet from using status endpoint */ // 防止usbnet使用状态端点
	dev->status = NULL; // 将状态端点设置为空

	/* save subdriver struct for suspend/resume wrappers */ // 保存子驱动结构体用于挂起/恢复包装函数
	info->subdriver = subdriver; // 保存子驱动指针

err: // 错误处理标签
	return rv; // 返回结果
}

static int qmi_wwan_bind(struct usbnet *dev, struct usb_interface *intf) // 定义绑定函数
{
	int status = -1; // 定义状态变量，初始值为-1
	u8 *buf = intf->cur_altsetting->extra; // 指向接口额外描述符的指针
	int len = intf->cur_altsetting->extralen; // 额外描述符的长度
	struct usb_interface_descriptor *desc = &intf->cur_altsetting->desc; // 接口描述符指针
	struct usb_cdc_union_desc *cdc_union = NULL; // CDC联合描述符指针
	struct usb_cdc_ether_desc *cdc_ether = NULL; // CDC以太网描述符指针
	u32 found = 0; // 用于记录已找到的描述符类型
	struct usb_driver *driver = driver_of(intf); // 获取接口的驱动
	struct qmi_wwan_state *info = (void *)&dev->data; // 获取QMI WWAN状态信息

	BUILD_BUG_ON((sizeof(((struct usbnet *)0)->data) < // 编译时检查usbnet数据区域大小是否足够
		      sizeof(struct qmi_wwan_state)));

	/* set up initial state */ // 设置初始状态
	info->control = intf; // 设置控制接口为当前接口
	info->data = intf; // 设置数据接口为当前接口
        /*add by zhangqingyun@meigsmart.com begain // 添加zhangqingyun的修改开始
	/* and a number of CDC descriptors */ // 解析一系列CDC描述符
	while (len > 3) { // 当剩余长度大于3时循环
		struct usb_descriptor_header *h = (void *)buf; // 将buf转换为描述符头部指针

		/* ignore any misplaced descriptors */ // 忽略任何错位的描述符
		if (h->bDescriptorType != USB_DT_CS_INTERFACE) // 如果描述符类型不是CS_INTERFACE
			goto next_desc; // 跳到下一个描述符

		/* buf[2] is CDC descriptor subtype */ // buf[2]是CDC描述符子类型
		switch (buf[2]) { // 根据子类型处理
		case USB_CDC_HEADER_TYPE: // CDC头部类型
			if (found & 1 << USB_CDC_HEADER_TYPE) { // 如果已经找到过该类型
				dev_dbg(&intf->dev, "extra CDC header\n"); // 打印调试信息
				goto err; // 跳转到错误处理
			}
			if (h->bLength != sizeof(struct usb_cdc_header_desc)) { // 如果长度不匹配
				dev_dbg(&intf->dev, "CDC header len %u\n", // 打印调试信息
					h->bLength);
				goto err; // 跳转到错误处理
			}
			break;
		case USB_CDC_UNION_TYPE: // CDC联合类型
			if (found & 1 << USB_CDC_UNION_TYPE) { // 如果已经找到过该类型
				dev_dbg(&intf->dev, "extra CDC union\n"); // 打印调试信息
				goto err; // 跳转到错误处理
			}
			if (h->bLength != sizeof(struct usb_cdc_union_desc)) { // 如果长度不匹配
				dev_dbg(&intf->dev, "CDC union len %u\n", // 打印调试信息
					h->bLength);
				goto err; // 跳转到错误处理
			}
			cdc_union = (struct usb_cdc_union_desc *)buf; // 记录联合描述符指针
			break;
		case USB_CDC_ETHERNET_TYPE: // CDC以太网类型
			if (found & 1 << USB_CDC_ETHERNET_TYPE) { // 如果已经找到过该类型
				dev_dbg(&intf->dev, "extra CDC ether\n"); // 打印调试信息
				goto err; // 跳转到错误处理
			}
			if (h->bLength != sizeof(struct usb_cdc_ether_desc)) { // 如果长度不匹配
				dev_dbg(&intf->dev, "CDC ether len %u\n", // 打印调试信息
					h->bLength);
				goto err; // 跳转到错误处理
			}
			cdc_ether = (struct usb_cdc_ether_desc *)buf; // 记录以太网描述符指针
			break;
		}

		/* Remember which CDC functional descriptors we've seen.  Works
		 * for all types we care about, of which USB_CDC_ETHERNET_TYPE
		 * (0x0f) is the highest numbered
		 */
		if (buf[2] < 32) // 如果子类型编号小于32
			found |= 1 << buf[2]; // 在found中设置对应位

next_desc: // 下一个描述符标签
		len -= h->bLength; // 从总长度中减去当前描述符长度
		buf += h->bLength; // 将buf指针向前移动
	}
        /*add by zhangqingyun@meigsmart.com end*/ // 添加zhangqingyun的修改结束
	/* Use separate control and data interfaces if we found a CDC Union */ // 如果找到了CDC联合描述符，则使用独立的控制和数据接口
	if (cdc_union) { // 如果找到了联合描述符
		info->data = usb_ifnum_to_if(dev->udev, // 获取数据接口
					     cdc_union->bSlaveInterface0);
		if (desc->bInterfaceNumber != cdc_union->bMasterInterface0 || // 如果主接口号不匹配或数据接口为空
		    !info->data) {
			dev_err(&intf->dev, // 打印错误信息
				"bogus CDC Union: master=%u, slave=%u\n",
				cdc_union->bMasterInterface0,
				cdc_union->bSlaveInterface0);
			goto err; // 跳转到错误处理
		}
	}

	/* errors aren't fatal - we can live with the dynamic address */ // 错误不是致命的 - 我们可以使用动态地址
	if (cdc_ether) { // 如果找到了以太网描述符
		dev->hard_mtu = le16_to_cpu(cdc_ether->wMaxSegmentSize); // 设置最大段大小
		usbnet_get_ethernet_addr(dev, cdc_ether->iMACAddress); // 获取以太网地址
	}

	/* claim data interface and set it up */ // 声明数据接口并设置
	if (info->control != info->data) { // 如果控制接口不等于数据接口
		status = usb_driver_claim_interface(driver, info->data, dev); // 声明数据接口
		if (status < 0) // 如果声明失败
			goto err; // 跳转到错误处理
	}

	status = qmi_wwan_register_subdriver(dev); // 注册子驱动
	if (status < 0 && info->control != info->data) { // 如果注册失败且控制接口不等于数据接口
		usb_set_intfdata(info->data, NULL); // 清除数据接口的数据
		usb_driver_release_interface(driver, info->data); // 释放数据接口
	}

	/* Never use the same address on both ends of the link, even
	 * if the buggy firmware told us to.
	 */
	if (ether_addr_equal(dev->net->dev_addr, default_modem_addr)) // 如果设备地址等于默认调制解调器地址
		eth_hw_addr_random(dev->net); // 生成随机硬件地址

	/* make MAC addr easily distinguishable from an IP header */ // 使MAC地址易于与IP头部区分
	if (possibly_iphdr(dev->net->dev_addr)) { // 如果MAC地址可能被误认为IP头部
		dev->net->dev_addr[0] |= 0x02;	/* set local assignment bit */ // 设置本地分配位
		dev->net->dev_addr[0] &= 0xbf;	/* clear "IP" bit */ // 清除"IP"位
	}
	dev->net->netdev_ops = &qmi_wwan_netdev_ops; // 设置网络设备操作函数

	//dev->rx_urb_size = 7600; // 注释掉的接收URB大小设置

#if 1 //Added by zhangqingyun@meigsmart.com // 添加zhangqingyun的修改
	if (dev->udev->descriptor.idVendor == cpu_to_le16(0x2C7C) || // 检查供应商ID
	    dev->udev->descriptor.idVendor == cpu_to_le16(0x05c6) ||
            dev->udev->descriptor.idVendor == cpu_to_le16(0x2dee)) {
		dev_info(&intf->dev, "MeigSmart slm750 slm730 srm815 work on RawIP mode\n"); // 打印信息
		dev->net->flags |= IFF_NOARP; // 设置不使用ARP标志
	/* make MAC addr easily distinguishable from an IP header */ // 使MAC地址易于与IP头部区分
	usb_control_msg(interface_to_usbdev(intf), // 发送控制消息
				usb_sndctrlpipe(interface_to_usbdev(intf), 0), // 创建控制管道
				0x22, //USB_CDC_REQ_SET_CONTROL_LINE_STATE // 设置控制线状态请求
				0x21, //USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE // 控制传输类型
				1, //active CDC DTR // 激活DTR
				intf->cur_altsetting->desc.bInterfaceNumber, // 接口号
				NULL, 0, 100); // 无数据，长度0，超时100
	}
#endif

err: // 错误处理标签
	return status; // 返回状态
}

static void qmi_wwan_unbind(struct usbnet *dev, struct usb_interface *intf) // 定义解绑函数
{
	struct qmi_wwan_state *info = (void *)&dev->data; // 获取QMI WWAN状态信息
	struct usb_driver *driver = driver_of(intf); // 获取接口的驱动
	struct usb_interface *other; // 定义另一个接口指针

	if (info->subdriver && info->subdriver->disconnect) // 如果子驱动存在且有断开连接函数
		info->subdriver->disconnect(info->control); // 断开子驱动连接

	/* allow user to unbind using either control or data */ // 允许用户使用控制或数据接口来解绑
	if (intf == info->control) // 如果当前接口是控制接口
		other = info->data; // 另一个接口是数据接口
	else
		other = info->control; // 否则是控制接口

	/* only if not shared */ // 仅当接口不共享时
	if (other && intf != other) { // 如果另一个接口存在且与当前接口不同
		usb_set_intfdata(other, NULL); // 清除另一个接口的数据
		usb_driver_release_interface(driver, other); // 释放另一个接口
	}

	info->subdriver = NULL; // 清空子驱动指针
	info->data = NULL; // 清空数据接口指针
	info->control = NULL; // 清空控制接口指针
}

/* suspend/resume wrappers calling both usbnet and the cdc-wdm
 * subdriver if present.
 *
 * NOTE: cdc-wdm also supports pre/post_reset, but we cannot provide
 * wrappers for those without adding usbnet reset support first.
 */
static int qmi_wwan_suspend(struct usb_interface *intf, pm_message_t message) // 定义挂起函数
{
	struct usbnet *dev = usb_get_intfdata(intf); // 获取USB接口关联的usbnet设备
	struct qmi_wwan_state *info = (void *)&dev->data; // 获取QMI WWAN状态信息
	int ret; // 定义返回值变量

	/* Both usbnet_suspend() and subdriver->suspend() MUST return 0
	 * in system sleep context, otherwise, the resume callback has
	 * to recover device from previous suspend failure.
	 */
	ret = usbnet_suspend(intf, message); // 调用usbnet挂起函数
	if (ret < 0) // 如果挂起失败
		goto err; // 跳转到错误处理

	if (intf == info->control && info->subdriver && // 如果当前接口是控制接口且子驱动存在
	    info->subdriver->suspend)
		ret = info->subdriver->suspend(intf, message); // 调用子驱动挂起函数
	if (ret < 0) // 如果子驱动挂起失败
		usbnet_resume(intf); // 恢复usbnet
err: // 错误处理标签
	return ret; // 返回结果
}

static int qmi_wwan_resume(struct usb_interface *intf) // 定义恢复函数
{
	struct usbnet *dev = usb_get_intfdata(intf); // 获取USB接口关联的usbnet设备
	struct qmi_wwan_state *info = (void *)&dev->data; // 获取QMI WWAN状态信息
	int ret = 0; // 定义返回值变量，初始为0
	bool callsub = (intf == info->control && info->subdriver && // 判断是否需要调用子驱动恢复
			info->subdriver->resume);

	if (callsub) // 如果需要调用子驱动恢复
		ret = info->subdriver->resume(intf); // 调用子驱动恢复函数
	if (ret < 0) // 如果子驱动恢复失败
		goto err; // 跳转到错误处理
	ret = usbnet_resume(intf); // 调用usbnet恢复函数
	if (ret < 0 && callsub) // 如果usbnet恢复失败且之前调用了子驱动恢复
		info->subdriver->suspend(intf, PMSG_SUSPEND); // 再次挂起子驱动
err: // 错误处理标签
	return ret; // 返回结果
}

static const struct driver_info	qmi_wwan_info = { // 定义驱动信息结构体
	.description	= "WWAN/QMI device", // 设备描述
	.flags		= FLAG_WWAN | FLAG_SEND_ZLP, // 驱动标志
	.bind		= qmi_wwan_bind, // 绑定函数
	.unbind		= qmi_wwan_unbind, // 解绑函数
	.manage_power	= qmi_wwan_manage_power, // 电源管理函数
	.rx_fixup       = qmi_wwan_rx_fixup, // 接收修复函数
#if 1 //Added by zhangqingyun@meigsmart.com // 添加zhangqingyun的修改
	.tx_fixup = qmi_wwan_tx_fixup, // 发送修复函数
#endif
};

#define HUAWEI_VENDOR_ID	0x12D1 // 定义华为供应商ID

/* map QMI/wwan function by a fixed interface number */ // 通过固定接口号映射QMI/wwan功能
#define QMI_FIXED_INTF(vend, prod, num) \ // 定义QMI固定接口宏
	USB_DEVICE_INTERFACE_NUMBER(vend, prod, num), \ // USB设备接口号匹配
	.driver_info = (unsigned long)&qmi_wwan_info // 设置驱动信息

/* Gobi 1000 QMI/wwan interface number is 3 according to qcserial */ // 根据qcserial，Gobi 1000 QMI/wwan接口号是3
#define QMI_GOBI1K_DEVICE(vend, prod) \ // 定义QMI Gobi 1000设备宏
	QMI_FIXED_INTF(vend, prod, 3) // 固定接口号为3

/* Gobi 2000/3000 QMI/wwan interface number is 0 according to qcserial */ // 根据qcserial，Gobi 2000/3000 QMI/wwan接口号是0
#define QMI_GOBI_DEVICE(vend, prod) \ // 定义QMI Gobi 2000/3000设备宏
	QMI_FIXED_INTF(vend, prod, 0) // 固定接口号为0

static const struct usb_device_id products[] = { // 定义支持的USB设备ID表
#if 1 //Added by Quectel // 添加Quectel的修改
#ifndef QMI_FIXED_INTF // 如果QMI_FIXED_INTF未定义
/* map QMI/wwan function by a fixed interface number */ // 通过固定接口号映射QMI/wwan功能
#define QMI_FIXED_INTF(vend, prod, num) \ // 重新定义QMI固定接口宏
		.match_flags = USB_DEVICE_ID_MATCH_DEVICE | USB_DEVICE_ID_MATCH_INT_INFO, \ // 匹配设备和接口信息
		.idVendor = vend, \ // 供应商ID
		.idProduct = prod, \ // 产品ID
		.bInterfaceClass = 0xff, \ // 接口类
		.bInterfaceSubClass = 0xff, \ // 接口子类
		.bInterfaceProtocol = 0xff, \ // 接口协议
		.driver_info = (unsigned long)&qmi_wwan_force_int##num, // 驱动信息
#endif
	{ QMI_FIXED_INTF(0x2C7C, 0x0125, 4) }, /* Quectel EC25/EC20 R2.0 */ // Quectel EC25/EC20 R2.0，接口4
	{ QMI_FIXED_INTF(0x2C7C, 0x0121, 4) }, /* Quectel EC21 */ // Quectel EC21，接口4
	{ QMI_FIXED_INTF(0x05c6, 0xf601, 5) }, /* MeigLink SLM750 SLM730 SLM750VR2.0*/ // MeigLink SLM750 SLM730 SLM750VR2.0，接口5
        { QMI_FIXED_INTF(0x2dee, 0x4d22, 5) }, /*MeigLink SRM815*/ // MeigLink SRM815，接口5
#endif
	/* 1. CDC ECM like devices match on the control interface */ // 1. 类似CDC ECM的设备在控制接口上匹配
	{	/* Huawei E392, E398 and possibly others sharing both device id and more... */ // 华为E392, E398等设备
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 9), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Vodafone/Huawei K5005 (12d1:14c8) and similar modems */ // Vodafone/Huawei K5005等调制解调器
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 57), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* HUAWEI_INTERFACE_NDIS_CONTROL_QUALCOMM */ // 华为NDIS控制接口
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 0x01, 0x69), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},

	/* 2. Combined interface devices matching on class+protocol */ // 2. 组合接口设备通过类+协议匹配
	{	/* Huawei E367 and possibly others in "Windows mode" */ // 华为E367等在"Windows模式"下的设备
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 7), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Huawei E392, E398 and possibly others in "Windows mode" */ // 华为E392, E398等在"Windows模式"下的设备
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 1, 17), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* HUAWEI_NDIS_SINGLE_INTERFACE_VDF */ // 华为NDIS单接口VDF
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 0x01, 0x37), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* HUAWEI_INTERFACE_NDIS_HW_QUALCOMM */ // 华为NDIS硬件Qualcomm接口
		USB_VENDOR_AND_INTERFACE_INFO(HUAWEI_VENDOR_ID, USB_CLASS_VENDOR_SPEC, 0x01, 0x67), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Pantech UML290, P4200 and more */ // Pantech UML290, P4200等设备
		USB_VENDOR_AND_INTERFACE_INFO(0x106c, USB_CLASS_VENDOR_SPEC, 0xf0, 0xff), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Pantech UML290 - newer firmware */ // Pantech UML290 - 新固件
		USB_VENDOR_AND_INTERFACE_INFO(0x106c, USB_CLASS_VENDOR_SPEC, 0xf1, 0xff), // 匹配供应商和接口信息
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Novatel USB551L and MC551 */ // Novatel USB551L和MC551
		USB_DEVICE_AND_INTERFACE_INFO(0x1410, 0xb001, // 匹配设备和接口信息
		                              USB_CLASS_COMM, // 通信类
		                              USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
		                              USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Novatel E362 */
		USB_DEVICE_AND_INTERFACE_INFO(0x1410, 0x9010, // 匹配设备和接口信息
		                              USB_CLASS_COMM, // 通信类
		                              USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
		                              USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Novatel Expedite E371 */
		USB_DEVICE_AND_INTERFACE_INFO(0x1410, 0x9011, // 匹配设备和接口信息
		                              USB_CLASS_COMM, // 通信类
		                              USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
		                              USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Dell Wireless 5800 (Novatel E362) */
		USB_DEVICE_AND_INTERFACE_INFO(0x413C, 0x8195, // 匹配设备和接口信息
					      USB_CLASS_COMM, // 通信类
					      USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
					      USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Dell Wireless 5800 V2 (Novatel E362) */
		USB_DEVICE_AND_INTERFACE_INFO(0x413C, 0x8196, // 匹配设备和接口信息
					      USB_CLASS_COMM, // 通信类
					      USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
					      USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* Dell Wireless 5804 (Novatel E371) */
		USB_DEVICE_AND_INTERFACE_INFO(0x413C, 0x819b, // 匹配设备和接口信息
					      USB_CLASS_COMM, // 通信类
					      USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
					      USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* ADU960S */
		USB_DEVICE_AND_INTERFACE_INFO(0x16d5, 0x650a, // 匹配设备和接口信息
					      USB_CLASS_COMM, // 通信类
					      USB_CDC_SUBCLASS_ETHERNET, // CDC以太网子类
					      USB_CDC_PROTO_NONE), // CDC无协议
		.driver_info        = (unsigned long)&qmi_wwan_info, // 驱动信息
	},
	{	/* HP lt4112 LTE/HSPA+ Gobi 4G Module (Huawei me906e) */
		USB_DEVICE_AND_INTERFACE_INFO(0x03f0, 0x581d, USB_CLASS_VENDOR_SPEC, 1, 7), // 匹配设备和接口信息
		.driver_info = (unsigned long)&qmi_wwan_info, // 驱动信息
	},

	/* 3. Combined interface devices matching on interface number */ // 3. 组合接口设备通过接口号匹配
	{QMI_FIXED_INTF(0x0408, 0xea42, 4)},	/* Yota / Megafon M100-1 */
	{QMI_FIXED_INTF(0x05c6, 0x7000, 0)},
	{QMI_FIXED_INTF(0x05c6, 0x7001, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7002, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7101, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7101, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x7101, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x7102, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x7102, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x7102, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x8000, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x8001, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9000, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9003, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9005, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x900a, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x900b, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x900c, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x900c, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x900c, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x900d, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x900f, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x900f, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x900f, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9010, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9010, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9011, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9011, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9021, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x9022, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x9025, 4)},	/* Alcatel-sbell ASB TL131 TDD LTE  (China Mobile) */
	{QMI_FIXED_INTF(0x05c6, 0x9026, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x902e, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9031, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9032, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9033, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9033, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9033, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9033, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9034, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9034, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9034, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9034, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9034, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9035, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9036, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9037, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9038, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x903b, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x903c, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x903d, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x903e, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9043, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9046, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9046, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9046, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9047, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x9047, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9047, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9048, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9048, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9048, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9048, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9048, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x904c, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x904c, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x904c, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x904c, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x9050, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9052, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9053, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9053, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9054, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9054, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9055, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9055, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9055, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9055, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9055, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9056, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x9062, 9)},
	{QMI_FIXED_INTF(0x05c6, 0x9064, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9065, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9065, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9066, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9066, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9067, 1)},
	{QMI_FIXED_INTF(0x05c6, 0x9068, 2)},
	{QMI_FIXED_INTF(0x05c6, 0x9068, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9068, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9068, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9068, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9068, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9069, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9069, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9069, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9069, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x9070, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9070, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9075, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9076, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9076, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9076, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9076, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9076, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x9077, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9077, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9077, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9077, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9078, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9079, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x9079, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9079, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9079, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9079, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x9080, 5)},
	{QMI_FIXED_INTF(0x05c6, 0x9080, 6)},
	{QMI_FIXED_INTF(0x05c6, 0x9080, 7)},
	{QMI_FIXED_INTF(0x05c6, 0x9080, 8)},
	{QMI_FIXED_INTF(0x05c6, 0x9083, 3)},
	{QMI_FIXED_INTF(0x05c6, 0x9084, 4)},
	{QMI_FIXED_INTF(0x05c6, 0x920d, 0)},
	{QMI_FIXED_INTF(0x05c6, 0x920d, 5)},
	{QMI_FIXED_INTF(0x0846, 0x68a2, 8)},
	{QMI_FIXED_INTF(0x12d1, 0x140c, 1)},	/* Huawei E173 */
	{QMI_FIXED_INTF(0x12d1, 0x14ac, 1)},	/* Huawei E1820 */
	{QMI_FIXED_INTF(0x16d8, 0x6003, 0)},	/* CMOTech 6003 */
	{QMI_FIXED_INTF(0x16d8, 0x6007, 0)},	/* CMOTech CHE-628S */
	{QMI_FIXED_INTF(0x16d8, 0x6008, 0)},	/* CMOTech CMU-301 */
	{QMI_FIXED_INTF(0x16d8, 0x6280, 0)},	/* CMOTech CHU-628 */
	{QMI_FIXED_INTF(0x16d8, 0x7001, 0)},	/* CMOTech CHU-720S */
	{QMI_FIXED_INTF(0x16d8, 0x7002, 0)},	/* CMOTech 7002 */
	{QMI_FIXED_INTF(0x16d8, 0x7003, 4)},	/* CMOTech CHU-629K */
	{QMI_FIXED_INTF(0x16d8, 0x7004, 3)},	/* CMOTech 7004 */
	{QMI_FIXED_INTF(0x16d8, 0x7006, 5)},	/* CMOTech CGU-629 */
	{QMI_FIXED_INTF(0x16d8, 0x700a, 4)},	/* CMOTech CHU-629S */
	{QMI_FIXED_INTF(0x16d8, 0x7211, 0)},	/* CMOTech CHU-720I */
	{QMI_FIXED_INTF(0x16d8, 0x7212, 0)},	/* CMOTech 7212 */
	{QMI_FIXED_INTF(0x16d8, 0x7213, 0)},	/* CMOTech 7213 */
	{QMI_FIXED_INTF(0x16d8, 0x7251, 1)},	/* CMOTech 7251 */
	{QMI_FIXED_INTF(0x16d8, 0x7252, 1)},	/* CMOTech 7252 */
	{QMI_FIXED_INTF(0x16d8, 0x7253, 1)},	/* CMOTech 7253 */
	{QMI_FIXED_INTF(0x19d2, 0x0002, 1)},
	{QMI_FIXED_INTF(0x19d2, 0x0012, 1)},
	{QMI_FIXED_INTF(0x19d2, 0x0017, 3)},
	{QMI_FIXED_INTF(0x19d2, 0x0019, 3)},	/* ONDA MT689DC */
	{QMI_FIXED_INTF(0x19d2, 0x0021, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0025, 1)},
	{QMI_FIXED_INTF(0x19d2, 0x0031, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0042, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0049, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0052, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0055, 1)},	/* ZTE (Vodafone) K3520-Z */
	{QMI_FIXED_INTF(0x19d2, 0x0058, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0063, 4)},	/* ZTE (Vodafone) K3565-Z */
	{QMI_FIXED_INTF(0x19d2, 0x0104, 4)},	/* ZTE (Vodafone) K4505-Z */
	{QMI_FIXED_INTF(0x19d2, 0x0113, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0118, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0121, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0123, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0124, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0125, 6)},
	{QMI_FIXED_INTF(0x19d2, 0x0126, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0130, 1)},
	{QMI_FIXED_INTF(0x19d2, 0x0133, 3)},
	{QMI_FIXED_INTF(0x19d2, 0x0141, 5)},
	{QMI_FIXED_INTF(0x19d2, 0x0157, 5)},	/* ZTE MF683 */
	{QMI_FIXED_INTF(0x19d2, 0x0158, 3)},
	{QMI_FIXED_INTF(0x19d2, 0x0167, 4)},	/* ZTE MF820D */
	{QMI_FIXED_INTF(0x19d2, 0x0168, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x0176, 3)},
	{QMI_FIXED_INTF(0x19d2, 0x0178, 3)},
	{QMI_FIXED_INTF(0x19d2, 0x0191, 4)},	/* ZTE EuFi890 */
	{QMI_FIXED_INTF(0x19d2, 0x0199, 1)},	/* ZTE MF820S */
	{QMI_FIXED_INTF(0x19d2, 0x0200, 1)},
	{QMI_FIXED_INTF(0x19d2, 0x0257, 3)},	/* ZTE MF821 */
	{QMI_FIXED_INTF(0x19d2, 0x0265, 4)},	/* ONDA MT8205 4G LTE */
	{QMI_FIXED_INTF(0x19d2, 0x0284, 4)},	/* ZTE MF880 */
	{QMI_FIXED_INTF(0x19d2, 0x0326, 4)},	/* ZTE MF821D */
	{QMI_FIXED_INTF(0x19d2, 0x0412, 4)},	/* Telewell TW-LTE 4G */
	{QMI_FIXED_INTF(0x19d2, 0x1008, 4)},	/* ZTE (Vodafone) K3570-Z */
	{QMI_FIXED_INTF(0x19d2, 0x1010, 4)},	/* ZTE (Vodafone) K3571-Z */
	{QMI_FIXED_INTF(0x19d2, 0x1012, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1018, 3)},	/* ZTE (Vodafone) K5006-Z */
	{QMI_FIXED_INTF(0x19d2, 0x1021, 2)},
	{QMI_FIXED_INTF(0x19d2, 0x1245, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1247, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1252, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1254, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1255, 3)},
	{QMI_FIXED_INTF(0x19d2, 0x1255, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1256, 4)},
	{QMI_FIXED_INTF(0x19d2, 0x1270, 5)},	/* ZTE MF667 */
	{QMI_FIXED_INTF(0x19d2, 0x1401, 2)},
	{QMI_FIXED_INTF(0x19d2, 0x1402, 2)},	/* ZTE MF60 */
	{QMI_FIXED_INTF(0x19d2, 0x1424, 2)},
	{QMI_FIXED_INTF(0x19d2, 0x1425, 2)},
	{QMI_FIXED_INTF(0x19d2, 0x1426, 2)},	/* ZTE MF91 */
	{QMI_FIXED_INTF(0x19d2, 0x1428, 2)},	/* Telewell TW-LTE 4G v2 */
	{QMI_FIXED_INTF(0x19d2, 0x2002, 4)},	/* ZTE (Vodafone) K3765-Z */
	{QMI_FIXED_INTF(0x2001, 0x7e19, 4)},	/* D-Link DWM-221 B1 */
	{QMI_FIXED_INTF(0x0f3d, 0x68a2, 8)},    /* Sierra Wireless MC7700 */
	{QMI_FIXED_INTF(0x114f, 0x68a2, 8)},    /* Sierra Wireless MC7750 */
	{QMI_FIXED_INTF(0x1199, 0x68a2, 8)},	/* Sierra Wireless MC7710 in QMI mode */
	{QMI_FIXED_INTF(0x1199, 0x68a2, 19)},	/* Sierra Wireless MC7710 in QMI mode */
	{QMI_FIXED_INTF(0x1199, 0x68c0, 8)},	/* Sierra Wireless MC73xx */
	{QMI_FIXED_INTF(0x1199, 0x68c0, 10)},	/* Sierra Wireless MC73xx */
	{QMI_FIXED_INTF(0x1199, 0x901c, 8)},    /* Sierra Wireless EM7700 */
	{QMI_FIXED_INTF(0x1199, 0x901f, 8)},    /* Sierra Wireless EM7355 */
	{QMI_FIXED_INTF(0x1199, 0x9041, 8)},	/* Sierra Wireless MC7305/MC7355 */
	{QMI_FIXED_INTF(0x1199, 0x9051, 8)},	/* Netgear AirCard 340U */
	{QMI_FIXED_INTF(0x1199, 0x9053, 8)},	/* Sierra Wireless Modem */
	{QMI_FIXED_INTF(0x1199, 0x9054, 8)},	/* Sierra Wireless Modem */
	{QMI_FIXED_INTF(0x1199, 0x9055, 8)},	/* Netgear AirCard 341U */
	{QMI_FIXED_INTF(0x1199, 0x9056, 8)},	/* Sierra Wireless Modem */
	{QMI_FIXED_INTF(0x1199, 0x9057, 8)},
	{QMI_FIXED_INTF(0x1199, 0x9061, 8)},	/* Sierra Wireless Modem */
	{QMI_FIXED_INTF(0x1199, 0x9070, 8)},	/* Sierra Wireless MC74xx/EM74xx */
	{QMI_FIXED_INTF(0x1199, 0x9070, 10)},	/* Sierra Wireless MC74xx/EM74xx */
	{QMI_FIXED_INTF(0x1199, 0x9071, 8)},	/* Sierra Wireless MC74xx */
	{QMI_FIXED_INTF(0x1199, 0x9071, 10)},	/* Sierra Wireless MC74xx */
	{QMI_FIXED_INTF(0x1199, 0x9079, 8)},	/* Sierra Wireless EM74xx */
	{QMI_FIXED_INTF(0x1199, 0x9079, 10)},	/* Sierra Wireless EM74xx */
	{QMI_FIXED_INTF(0x1bbb, 0x011e, 4)},	/* Telekom Speedstick LTE II (Alcatel One Touch L100V LTE) */
	{QMI_FIXED_INTF(0x1bbb, 0x0203, 2)},	/* Alcatel L800MA */
	{QMI_FIXED_INTF(0x2357, 0x0201, 4)},	/* TP-LINK HSUPA Modem MA180 */
	{QMI_FIXED_INTF(0x2357, 0x9000, 4)},	/* TP-LINK MA260 */
	{QMI_FIXED_INTF(0x1bc7, 0x1200, 5)},	/* Telit LE920 */
	{QMI_FIXED_INTF(0x1bc7, 0x1201, 2)},	/* Telit LE920 */
	{QMI_FIXED_INTF(0x1c9e, 0x9b01, 3)},	/* XS Stick W100-2 from 4G Systems */
	{QMI_FIXED_INTF(0x0b3c, 0xc000, 4)},	/* Olivetti Olicard 100 */
	{QMI_FIXED_INTF(0x0b3c, 0xc001, 4)},	/* Olivetti Olicard 120 */
	{QMI_FIXED_INTF(0x0b3c, 0xc002, 4)},	/* Olivetti Olicard 140 */
	{QMI_FIXED_INTF(0x0b3c, 0xc004, 6)},	/* Olivetti Olicard 155 */
	{QMI_FIXED_INTF(0x0b3c, 0xc005, 6)},	/* Olivetti Olicard 200 */
	{QMI_FIXED_INTF(0x0b3c, 0xc00a, 6)},	/* Olivetti Olicard 160 */
	{QMI_FIXED_INTF(0x0b3c, 0xc00b, 4)},	/* Olivetti Olicard 500 */
	{QMI_FIXED_INTF(0x1e2d, 0x0060, 4)},	/* Cinterion PLxx */
	{QMI_FIXED_INTF(0x1e2d, 0x0053, 4)},	/* Cinterion PHxx,PXxx */
	{QMI_FIXED_INTF(0x413c, 0x81a2, 8)},	/* Dell Wireless 5806 Gobi(TM) 4G LTE Mobile Broadband Card */
	{QMI_FIXED_INTF(0x413c, 0x81a3, 8)},	/* Dell Wireless 5570 HSPA+ (42Mbps) Mobile Broadband Card */
	{QMI_FIXED_INTF(0x413c, 0x81a4, 8)},	/* Dell Wireless 5570e HSPA+ (42Mbps) Mobile Broadband Card */
	{QMI_FIXED_INTF(0x413c, 0x81a8, 8)},	/* Dell Wireless 5808 Gobi(TM) 4G LTE Mobile Broadband Card */
	{QMI_FIXED_INTF(0x413c, 0x81a9, 8)},	/* Dell Wireless 5808e Gobi(TM) 4G LTE Mobile Broadband Card */

	/* 4. Gobi 1000 devices */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9212)},	/* Acer Gobi Modem Device */
	{QMI_GOBI1K_DEVICE(0x03f0, 0x1f1d)},	/* HP un2400 Gobi Modem Device */
	{QMI_GOBI1K_DEVICE(0x04da, 0x250d)},	/* Panasonic Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x413c, 0x8172)},	/* Dell Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa001)},	/* Novatel/Verizon USB-1000 */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa002)},	/* Novatel Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa003)},	/* Novatel Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa004)},	/* Novatel Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa005)},	/* Novatel Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa006)},	/* Novatel Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x1410, 0xa007)},	/* Novatel Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x0b05, 0x1776)},	/* Asus Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x19d2, 0xfff3)},	/* ONDA Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9001)},	/* Generic Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9002)},	/* Generic Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9202)},	/* Generic Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9203)},	/* Generic Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9222)},	/* Generic Gobi Modem device */
	{QMI_GOBI1K_DEVICE(0x05c6, 0x9009)},	/* Generic Gobi Modem device */

	/* 5. Gobi 2000 and 3000 devices */
	{QMI_GOBI_DEVICE(0x413c, 0x8186)},	/* Dell Gobi 2000 Modem device (N0218, VU936) */
	{QMI_GOBI_DEVICE(0x413c, 0x8194)},	/* Dell Gobi 3000 Composite */
	{QMI_GOBI_DEVICE(0x05c6, 0x920b)},	/* Generic Gobi 2000 Modem device */
	{QMI_GOBI_DEVICE(0x05c6, 0x9225)},	/* Sony Gobi 2000 Modem device (N0279, VU730) */
	{QMI_GOBI_DEVICE(0x05c6, 0x9245)},	/* Samsung Gobi 2000 Modem device (VL176) */
	{QMI_GOBI_DEVICE(0x03f0, 0x251d)},	/* HP Gobi 2000 Modem device (VP412) */
	{QMI_GOBI_DEVICE(0x05c6, 0x9215)},	/* Acer Gobi 2000 Modem device (VP413) */
	{QMI_FIXED_INTF(0x05c6, 0x9003, 4)},    /* Quectel UC20 */
	{QMI_FIXED_INTF(0x05c6, 0x9215, 4)},    /* Quectel EC20 */
	{QMI_GOBI_DEVICE(0x05c6, 0x9265)},	/* Asus Gobi 2000 Modem device (VR305) */
	{QMI_GOBI_DEVICE(0x05c6, 0x9235)},	/* Top Global Gobi 2000 Modem device (VR306) */
	{QMI_GOBI_DEVICE(0x05c6, 0x9275)},	/* iRex Technologies Gobi 2000 Modem device (VR307) */
	{QMI_GOBI_DEVICE(0x0af0, 0x8120)},	/* Option GTM681W */
	{QMI_GOBI_DEVICE(0x1199, 0x68a5)},	/* Sierra Wireless Modem */
	{QMI_GOBI_DEVICE(0x1199, 0x68a9)},	/* Sierra Wireless Modem */
	{QMI_GOBI_DEVICE(0x1199, 0x9001)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9002)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9003)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9004)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9005)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9006)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9007)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9008)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9009)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x900a)},	/* Sierra Wireless Gobi 2000 Modem device (VT773) */
	{QMI_GOBI_DEVICE(0x1199, 0x9011)},	/* Sierra Wireless Gobi 2000 Modem device (MC8305) */
	{QMI_GOBI_DEVICE(0x16d8, 0x8002)},	/* CMDTech Gobi 2000 Modem device (VU922) */
	{QMI_GOBI_DEVICE(0x05c6, 0x9205)},	/* Gobi 2000 Modem device */
	{QMI_GOBI_DEVICE(0x1199, 0x9013)},	/* Sierra Wireless Gobi 3000 Modem device (MC8355) */
	{QMI_GOBI_DEVICE(0x03f0, 0x371d)},	/* HP un2430 Mobile Broadband Module */
	{QMI_GOBI_DEVICE(0x1199, 0x9015)},	/* Sierra Wireless Gobi 3000 Modem device */
	{QMI_GOBI_DEVICE(0x1199, 0x9019)},	/* Sierra Wireless Gobi 3000 Modem device */
	{QMI_GOBI_DEVICE(0x1199, 0x901b)},	/* Sierra Wireless MC7770 */
	{QMI_GOBI_DEVICE(0x12d1, 0x14f1)},	/* Sony Gobi 3000 Composite */
	{QMI_GOBI_DEVICE(0x1410, 0xa021)},	/* Foxconn Gobi 3000 Modem device (Novatel E396) */

	{ }					/* END */
};
MODULE_DEVICE_TABLE(usb, products); // 导出设备表
//zhangqingyun add pid+vid+interfacenumber determine is ndis port or not // zhangqingyun添加PID+VID+接口号判断是否为NDIS端口
static bool ndis_detected(struct usb_interface *intf) // 定义检测NDIS端口的函数
{
	struct usb_device *dev = interface_to_usbdev(intf); // 获取USB设备

	if (dev->actconfig && // 如果活动配置存在
	    le16_to_cpu(dev->descriptor.idVendor) == 0x05c6 && // 供应商ID匹配
	    le16_to_cpu(dev->descriptor.idProduct) == 0x9215 && // 产品ID匹配
	    dev->actconfig->desc.bNumInterfaces == 5) { // 接口数量为5
		return true; // 返回true
	}
    /*zhangqingyun add start */ // zhangqingyun添加开始
	if (dev->actconfig && // 如果活动配置存在
	    le16_to_cpu(dev->descriptor.idVendor) == 0x05c6 && // 供应商ID匹配
	    le16_to_cpu(dev->descriptor.idProduct) == 0xf601 && // 产品ID匹配
	    dev->actconfig->desc.bNumInterfaces == 5) { // 接口数量为5
		dev_dbg(&intf->dev, "zhangqingyun detemine interface 5 is ndis port"); // 打印调试信息
		return true; // 返回true
	}
        if (dev->actconfig &&  // 如果活动配置存在
            le16_to_cpu(dev->descriptor.idVendor) == 0x2dee && // 供应商ID匹配
            le16_to_cpu(dev->descriptor.idProduct) == 0x4d22 && // 产品ID匹配
            dev->actconfig->desc.bNumInterfaces == 5){ // 接口数量为5
                dev_dbg(&intf->dev, "zhangqingyun detemine interface 5 is ndis port"); // 打印调试信息
                return true; // 返回true
        }
	/*zhangqingyun add end*/ // zhangqingyun添加结束
	return false; // 返回false
}

static int qmi_wwan_probe(struct usb_interface *intf, // 定义探测函数
			  const struct usb_device_id *prod) // 产品ID指针
{
	struct usb_device_id *id = (struct usb_device_id *)prod; // 将const指针转换为非const指针
	struct usb_interface_descriptor *desc = &intf->cur_altsetting->desc; // 获取接口描述符

	/* Workaround to enable dynamic IDs.  This disables usbnet
	 * blacklisting functionality.  Which, if required, can be
	 * reimplemented here by using a magic "blacklist" value
	 * instead of 0 in the static device id table
	 */
	if (!id->driver_info) { // 如果驱动信息为空
		dev_dbg(&intf->dev, "setting defaults for dynamic device id\n"); // 打印调试信息
		id->driver_info = (unsigned long)&qmi_wwan_info; // 设置默认驱动信息
	}

	/* where we've QMI on interface 5 instead of 0 */ // 在接口5上使用QMI而不是接口0
	if (ndis_detected(intf) && desc->bInterfaceNumber == 0) { // 如果检测到NDIS且当前接口号为0
		dev_dbg(&intf->dev, "skipping interface 0\n"); // 打印调试信息
		return -ENODEV; // 返回设备不存在错误
	}

	return usbnet_probe(intf, id); // 调用usbnet探测函数
}

static struct usb_driver qmi_wwan_driver = { // 定义USB驱动结构体
	.name		      = "qmi_wwan_m", // 驱动名称
	.id_table	      = products, // 设备ID表
	.probe		      = qmi_wwan_probe, // 探测函数
	.disconnect	      = usbnet_disconnect, // 断开连接函数
	.suspend	      = qmi_wwan_suspend, // 挂起函数
	.resume		      =	qmi_wwan_resume, // 恢复函数
	.reset_resume         = qmi_wwan_resume, // 重置恢复函数
	.supports_autosuspend = 1, // 支持自动挂起
	.disable_hub_initiated_lpm = 1, // 禁用Hub发起的LPM
};

module_usb_driver(qmi_wwan_driver); // 注册USB驱动

MODULE_AUTHOR("Bjørn Mork <bjorn@mork.no>"); // 模块作者
MODULE_DESCRIPTION("Qualcomm MSM Interface (QMI) WWAN driver"); // 模块描述
MODULE_LICENSE("GPL"); // 模块许可证
MODULE_VERSION(MEIG_WWAN_VERSION); // 模块版本





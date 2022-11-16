Linux* aQuantia AQtion Driver for the aQuantia Multi-Gigabit PCI Express Family
of Ethernet Adapters
=============================================================================

Contents
========

- Important Note
- In This Release
- Identifying Your Adapter
- Building and Installation
- Command Line Parameters
- Additional Configurations
- Antigua Flashless boot support
- Uninstall
- Support

IMPORTANT NOTE
==============

WARNING:
AQtion driver is built with the LRO (Large Receive Offload) feature enabled
by default.
This option offers the lowest CPU utilization for receives, but it is completely
incompatible with *routing/ip forwarding* and *bridging*.
If you need ip forwarding or bridging, please make sure to disable LRO using the
compile time options described in the LRO section below.
NB! If LRO is enabled, attempts to use ip forwarding or bridging can result in
low throughput or even a kernel panic.

In This Release
===============

This file describes the aQuantia AQtion Driver for the aQuantia Multi-Gigabit
PCI Express Family of Ethernet Adapters.
This driver supports Linux kernels >= 3.10, and includes support for x86_64 and
ARM Linux system.

This release contains a source tarball and (optionally) a src.rpm package.

Identifying Your Adapter
========================

The driver in this release is compatible with ethernet adapters based on:
 - AQC-100,
 - AQC-107,
 - AQC-108,
 - AQC-109,
 - AQC-111,
 - AQC-112,
 - AQC-113.


SFP+ Devices (for AQC-100 based adapters)
----------------------------------

This release was verified to work with passive Direct Attach Cables (DAC) and
SFP+/LC Optical Transceiver.

Building and Installation
=========================

To manually build this driver:
------------------------------------------------------------
1. Make sure you have all the packages required to build a standalone kernel
   module.
   On a debian-based systems you should at least install the following packages:

	sudo apt install linux-headers build-essential

2. Move the base driver tar file to the directory of your choice.
   For example, use /home/username/aquantia.
   Untar/unzip archive:

	cd ~/aquantia
	tar zxf Aquantia-AQtion-x.y.z.tar.gz

3. Change to the driver src directory:

	cd Aquantia-AQtion-x.y.z/

NB! Make sure that pathname doesn't contain whitespaces and special characters
    (e.g. brackets), because kernel build system doesn't support such paths
    unfortunately and the build will fail.

4. Compile the driver module:
	make

5. Unload the driver, if an older version is in use:
	sudo rmmod atlantic

5. Load the dependencies and the module itself:
	sudo make load

7. Install the driver
	sudo make install

driver will be installed into the following location:

	/lib/modules/`uname -r`/aquantia/atlantic.ko

NB! You might need to update initramfs image uponon install
(e.g. if atlantic.ko is a part of it, otherwise an old version will be
loaded from initramfs image on next reboot).
This is a potentially harmful operation, so 'make install' will check
if such an update is needed and will ask for your consent before actually
running update-initramfs / dracut.
Please make sure you understand the risks before choosing 'Y'!

Alternatively build and install the driver with dkms
------------------------------------------------------------
1. Make sure you have all the packages required to build a standalone kernel
   module.
   On Debian-based systems the following command can be used:

	sudo apt-get install linux-headers-`uname -r` build-essential gawk dkms

   On redhat-based systems the following command can be used:

	sudo yum install kernel-devel-`uname -r` gcc gcc-c++ make gawk dkms

2. Move the base driver tar file to the directory of your choice.
   For example, use /home/username/aquantia.
   Untar/unzip archive:

	cd ~/aquantia
	tar zxf Aquantia-AQtion-x.y.z.tar.gz

3. Change to the driver source directory:

	cd Aquantia-AQtion-x.y.z/

4. Build and install the driver:

	sudo ./dkms.sh install

driver will be installed into the following location:

	/lib/modules/`uname -r`/updates/dkms/atlantic.ko

Install the driver on Debian\Ubuntu using atlantic-x.y.z.deb
------------------------------------------------------------
1. Make sure you have all the packages required to build a standalone kernel
   module.
   Execute the command:
	sudo apt-get install linux-headers-`uname -r`

2. Move the atlantic-x.y.z.deb file to the directory of your choice.
   For example, use /home/username/aquantia.

3. Execute the following commands:
	cd /home/username/aquantia
	sudo apt-get install ./atlantic-x.y.z.deb

You can use "dpkg -l | grep -i atlantic" to verify that the driver has been
installed.

Alternatively you can use atlantic-x.y.z.noarch.rpm
------------------------------------------------------------
1. Make sure you have all the packages required to build a standalone kernel
   module.
   Execute the command:
	sudo yum install kernel-devel-`uname -r`

2. Move the atlantic-x.y.z.noarch.rpm file to the directory of your choice.
   For example, use /home/username/aquantia.

3. Execute the following commands:
	cd /home/username/aquantia
	sudo yum install ./atlantic-x.y.z.noarch.rpm

You can use "rpm -qa | grep -i atlantic" to verify that the driver has been
installed.

Check that the driver is working
------------------------------------------------------------

1. Verify that ethernet interface appears:
	ifconfig
   or
	ip addr show

   If there's no new interface in the output, then check the dmesg output.
   If you see a "Bad firmware detected" message there, please update the
   firmware on your ethernet card.

2. Assign an IP address to the interface
   (replace 'ethX' with an actual interface name):

	ifconfig ethX <IP_address> netmask <netmask>
   or
	ip addr add <IP_address> dev ethX

3. Verify that the interface works
   (replace '<IP_address>' with an actual IP address of another machine on
    the same subnet with the interface under test):

	ping  <IP_address>
   or (for IPv6)
	ping6 <IPv6_address>

4. Make sure you are using the correct version of the driver
   (replace 'ethX' with an actual interface name):

	ethtool -i ethX

Troubleshooting
-----------------------

Some distributions don't provide kernel sources ready for 3rdparty module build.
In general, the following could be used to prepare kernel source tree for build:

	sudo su
	cd /lib/modules/`uname -r`/build
	make oldconfig
	make prepare
	make modules_prepare

Configuration
=========================

Viewing Link Messages
---------------------
Link messages will not be displayed to the console, if the distribution is
restricting system messages.
In order to see network driver link messages on your console, set the dmesg
log level to eight by running:

	dmesg -n 8

NOTE: This setting is not saved across reboots.

Jumbo Frames
------------
This driver supports Jumbo Frames for all adapters. Jumbo Frames support is
enabled by changing the MTU to a value larger than the default (1500).
The maximum value for the MTU is 16000.
Use the `ip` command to increase the MTU size. For example:

	ip link set mtu 16000 dev enp1s0

ethtool
-------
This driver utilizes ethtool interface for driver configuration and diagnostics,
as well as displaying statistical information.
Make sure you have an up-to-date version of ethtool to use this functionality.

NAPI
----
This driver supports NAPI (Rx polling mode).

Supported ethtool options
============================

Viewing adapter settings
---------------------
	ethtool <ethX>

Output example:

  Settings for enp1s0:
    Supported ports: [ TP ]
    Supported link modes:   100baseT/Full
                            1000baseT/Full
                            10000baseT/Full
                            2500baseT/Full
                            5000baseT/Full
    Supported pause frame use: Symmetric
    Supports auto-negotiation: Yes
    Supported FEC modes: Not reported
    Advertised link modes:  100baseT/Full
                            1000baseT/Full
                            10000baseT/Full
                            2500baseT/Full
                            5000baseT/Full
    Advertised pause frame use: Symmetric
    Advertised auto-negotiation: Yes
    Advertised FEC modes: Not reported
    Speed: 10000Mb/s
    Duplex: Full
    Port: Twisted Pair
    PHYAD: 0
    Transceiver: internal
    Auto-negotiation: on
    MDI-X: Unknown
    Supports Wake-on: g
    Wake-on: d
    Link detected: yes

 ---
Note: AQrate speeds (2.5/5 Gb/s) will be displayed only on
   Linux kernels > 4.10.
   But the speeds themselves can be used even on older kernel version:
	ethtool -s eth0 autoneg off speed 2500

Note: AQC FW provides only information on actual negotiated pause frame usage.
   Link partner pause settings are not directly available.
   Thus, `Advertised pause frame use` actually shows negotiated settings.
   To see the real advertised settings, use `ethtool -a eth0`.

Viewing adapter information
---------------------
	ethtool -i <ethX>

Output example:
 driver: atlantic
 version: 2.3.1
 firmware-version: 3.1.78
 expansion-rom-version:
 bus-info: 0000:01:00.0
 supports-statistics: yes
 supports-test: no
 supports-eeprom-access: no
 supports-register-dump: yes
 supports-priv-flags: no

Viewing Ethernet adapter statistics:
---------------------
	ethtool -S <ethX>

Output example:
 NIC statistics:
     InPackets: 13238607
     InUCast: 13293852
     InMCast: 52
     InBCast: 3
     InErrorsMAC: 0
     OutPackets: 23703019
     OutUCast: 23704941
     OutMCast: 67
     OutBCast: 11
     InUCastOctects: 213182760
     OutUCastOctects: 22698443
     InMCastOctects: 6600
     OutMCastOctects: 8776
     InBCastOctects: 192
     OutBCastOctects: 704
     InOctects: 2131839552
     OutOctects: 226938073
     InPacketsDma: 95532300
     OutPacketsDma: 59503397
     InOctetsDma: 1137102462
     OutOctetsDma: 2394339518
     InDroppedDma: 0
     Queue[0] InPackets: 23567131
     Queue[0] OutPackets: 20070028
     Queue[0] InJumboPackets: 0
     Queue[0] InLroPackets: 0
     Queue[0] InErrors: 0
     Queue[1] InPackets: 45428967
     Queue[1] OutPackets: 11306178
     Queue[1] InJumboPackets: 0
     Queue[1] InLroPackets: 0
     Queue[1] InErrors: 0
     Queue[2] InPackets: 3187011
     Queue[2] OutPackets: 13080381
     Queue[2] InJumboPackets: 0
     Queue[2] InLroPackets: 0
     Queue[2] InErrors: 0
     Queue[3] InPackets: 23349136
     Queue[3] OutPackets: 15046810
     Queue[3] InJumboPackets: 0
     Queue[3] InLroPackets: 0
     Queue[3] InErrors: 0

Note: InErrorsMAC counts MAC level FCS checksum errors. Per Queue InErrors are
   checksum errors from driver point of view i.e., Rx erors at L2/L3/L4 levels. 

Disable GRO when routing/bridging
---------------------------------
Due to a known kernel issue, GRO must be turned off when routing/bridging.
This can be done by running:

	ethtool -K <ethX> gro off


Disable LRO when routing/bridging
---------------------------------
Due to a known kernel issue, LRO must be turned off when routing/bridging.
This can be done by running:

	ethtool -K <ethX> lro off

Interrupt coalescing support
---------------------------------
ITR mode, TX/RX coalescing timings could be viewed with:

	ethtool -c <ethX>

and changed with:

	ethtool -C <ethX> tx-usecs <usecs> rx-usecs <usecs>

To disable coalescing:

	ethtool -C <ethX> tx-usecs 0 rx-usecs 0 tx-max-frames 1 tx-max-frames 1

Wake on LAN support
 ---------------------------------

WOL support by magic packet:

	ethtool -s <ethX> wol g

To disable WOL:

	ethtool -s <ethX> wol d

Set and check the driver message level
---------------------------------

Set message level

	ethtool -s <ethX> msglvl <level>

Level values:

 0x0001 - general driver status.
 0x0002 - hardware probing.
 0x0004 - link state.
 0x0008 - periodic status check.
 0x0010 - interface being brought down.
 0x0020 - interface being brought up.
 0x0040 - receive error.
 0x0080 - transmit error.
 0x0200 - interrupt handling.
 0x0400 - transmit completion.
 0x0800 - receive completion.
 0x1000 - packet contents.
 0x2000 - hardware status.
 0x4000 - Wake-on-LAN status.

By default, the level of debugging messages is set to 0x0001
(general driver status).

Check message level

	ethtool <ethX> | grep "Current message level"

If you want to disable the output of messages

	ethtool -s <ethX> msglvl 0

RX flow rules (ntuple filters)
---------------------------------
This driver supports several rule types, but the order is fixed:
1. 16 VLAN ID rules
2. 16 L2 EtherType rules
3. 8 L3/L4 5-Tuple rules


This driver uses ethtool interface for configuring ntuple filters,
via "ethtool -N <device> <filter>".

Use the following command to enable/disable the RX flow rules:

	ethtool -K ethX ntuple <on|off>

When ntuple filters are disabled, the driver flushes all the previously
programmed user filters from both the driver cache and the hardware.
Thus, everything must be re-added when ntuple is re-enabled.

Since the order of the rules is, the location of filters is also fixed:
 - Locations 0 - 15 for VLAN ID filters
 - Locations 16 - 31 for L2 EtherType filters
 - Locations 32 - 39 for L3/L4 5-tuple filters (locations 32, 36 for IPv6)

The L3/L4 5-tuple (protocol, source and destination IP address, source and
destination TCP/UDP/SCTP port) is compared against 8 filters.
For IPv4, up to 8 source and destination addresses can be matched.
For IPv6, only 2 pairs of addresses are supported at maximum.
Source and destination ports are compared only for TCP/UDP/SCTP packets.

To add a filter that directs a packet to queue 5, use the
 <-N|-U|--config-nfc|--config-ntuple> switch:

	ethtool -N <ethX> flow-type udp4 src-ip 10.0.0.1 dst-ip 10.0.0.2 src-port 2000 dst-port 2001 action 5 <loc 32>

where:
 - action is the queue number.
 - loc is the rule number.

For "flow-type ip4|udp4|tcp4|sctp4|ip6|udp6|tcp6|sctp6" the loc value must be
between 32 and 39 ([32 .. 39]).
For "flow-type ip4|udp4|tcp4|sctp4|ip6|udp6|tcp6|sctp6" you can create:
 - up to 8 rules for IPv4 traffic;
 - up to 2 rules for IPv6 traffic.
In case of IPv6 the loc value must be either 32 or 36.
At the moment you can not use IPv4 and IPv6 filters at the same time.

Example filter for IPv6 filter traffic:

	sudo ethtool -N <ethX> flow-type tcp6 src-ip 2001:db8:0:f101::1 dst-ip 2001:db8:0:f101::2 action 1 loc 32
	sudo ethtool -N <ethX> flow-type ip6 src-ip 2001:db8:0:f101::2 dst-ip 2001:db8:0:f101::5 action -1 loc 36

Example filter for IPv4 filter traffic:

	sudo ethtool -N <ethX> flow-type udp4 src-ip 10.0.0.4 dst-ip 10.0.0.7 src-port 2000 dst-port 2001 loc 32
	sudo ethtool -N <ethX> flow-type tcp4 src-ip 10.0.0.3 dst-ip 10.0.0.9 src-port 2000 dst-port 2001 loc 33
	sudo ethtool -N <ethX> flow-type ip4 src-ip 10.0.0.6 dst-ip 10.0.0.4 loc 34

If you set action -1, then all traffic corresponding to the filter will be
discarded.
The maximum value action is 31.


The VLAN filter (VLAN id) is compared against 16 filters.
VLAN id must be accompanied by mask 0xF000.
This is required in order to distinguish VLAN filter from L2 Ethertype filter
with UserPriority, since both User Priority and VLAN ID are passed in the same
'vlan' parameter.

To add a filter that directs packets from VLAN 2001 to queue 5:
	ethtool -N <ethX> flow-type ip4 vlan 2001 m 0xF000 action 1 loc 0


L2 EtherType filters allows to filter packets by EtherType field or both
EtherType and User Priority (PCP) field of 802.1Q.
UserPriority (vlan) parameter must be accompanied by mask 0x1FFF.
This is required in order to distinguish VLAN filter from L2 Ethertype filter
with UserPriority, since both User Priority and VLAN ID are passed in the same
'vlan' parameter.

To add a filter that directs IP4 packess of priority 3 to queue 3:
	ethtool -N <ethX> flow-type ether proto 0x800 vlan 0x600 m 0x1FFF action 3 loc 16


To see the list of currently present filters:

	ethtool <-u|-n|--show-nfc|--show-ntuple> <ethX>

Rules can be deleted from the table itself. This is done using:

	sudo ethtool <-N|-U|--config-nfc|--config-ntuple> <ethX> delete <loc>

where:
 - loc is the number of the rule to delete.

Rx filters is an interface to load the filter table that funnels all flow
into queue 0 unless an alternative queue is specified using "action". In that
case, any flow that matches the filter criteria will be directed to the
appropriate queue.
RX filters are supported on all kernels starting from 2.6.30 (and later).

RSS for UDP
---------------------------------
Currently, NIC does not support RSS for fragmented IP packets, which leads to
an incorrect handling of RSS for fragmented UDP traffic.
To disable RSS for UDP one can use the following RX Flow L3/L4 rule:

	ethtool -N eth0 flow-type udp4 action 0 loc 32

UDP GSO hardware offload
---------------------------------
UDP GSO allows to boost UDP tx rates by offloading UDP headers allocation
into hardware. A special userspace socket option is required for this,
could be validated with /kernel/tools/testing/selftests/net/

	udpgso_bench_tx -u -4 -D 10.0.1.1 -s 6300 -S 100

Will cause sending out of 100 byte sized UDP packets formed from single
6300 bytes user buffer.

UDP GSO is configured by:

	ethtool -K eth0 tx-udp-segmentation on

Private flags (testing)
---------------------------------

Atlantic driver supports private flags for custom hardware-specific features:

	$ ethtool --show-priv-flags ethX

	Private flags for ethX:
	DMASystemLoopback  : off
	PKTSystemLoopback  : off
	DMANetworkLoopback : off
	PHYInternalLoopback: off
	PHYExternalLoopback: off
	Downshift          : on
	MediaDetect        : off

Example:

	$ ethtool --set-priv-flags ethX DMASystemLoopback on

DMASystemLoopback:   DMA Host loopback.
PKTSystemLoopback:   Packet buffer host loopback.
DMANetworkLoopback:  Network side loopback on DMA block.
PHYInternalLoopback: Internal loopback on Phy.
PHYExternalLoopback: External loopback on Phy (with loopback ethernet cable).
Downshift:           When `on`, enables link speed downgrade in case PHY sees
                     currently selected speed is constantly failing
MediaDetect:         When `on`, enables low-power autoneg in PHY

Self test
------------------------------------

Self test can be initiated using the following command:

	sudo ethtool -t enp3s0 offline|online

`online` mode will not run TDR diagnostics and will only return SNR data.
`offline` mode will also run TDR diagnostics, which causes temporary link drop.

Result values are coded as descibed below:

    TDR status values:

111 = Open Circuit (> 300Ω)
110 = High Mismatch (> 115Ω)
101 = Low Mismatch (< 85Ω)
100 = Short Circuit (< 30Ω)
011 = Connected to Pair D
010 = Connected to Pair C
001 = Connected to Pair B
000 = OK

    TDR distance:

The distance in meters, accurate to +-1m, of the first of the four worst
reflections

    TDR far distance:

Length estimate of pair distance, in meters

    SNR margin

The excess SNR that is enjoyed by the channel, over and above the minimum
SNR required to operate at a BER of 10e-12. It is reported with 0.1 dB of
resolution to an accuracy of 0.5 dB within the range of -12.7 dB to 12.7 dB.
The number is in offset binary, with 0.0 dB represented by 0x8000.

Command Line Parameters
=======================
The following command line parameters are supported by atlantic driver:

aq_itr -Interrupt throttling mode
----------------------------------------
Accepted values: 0, 1, 0xFFFF
Default value: 0xFFFF
0      - Disable interrupt throttling.
1      - Enable interrupt throttling and use specified tx and rx rates.
0xFFFF - Auto throttling mode. Driver will choose the best RX and TX
         interrupt throtting settings based on link speed.

aq_itr_tx - TX interrupt throttle rate
----------------------------------------
Accepted values: 0 - 0x1FF
Default value: 0
TX side throttling in microseconds. Adapter will setup maximum interrupt delay
to this value. Minimum interrupt delay will be a half of this value

aq_itr_rx - RX interrupt throttle rate
----------------------------------------
Accepted values: 0 - 0x1FF
Default value: 0
RX side throttling in microseconds. Adapter will setup maximum interrupt delay
to this value. Minimum interrupt delay will be a half of this value

Note: ITR settings could be changed in runtime by ethtool -c means (see below)

aq_rxpageorder
----------------------------------------
Default value: 0
RX page order override. Thats a power of 2 number of RX pages allocated for each
descriptor. Received descriptor size is still limited by AQ_CFG_RX_FRAME_MAX.
Increasing pageorder makes page reuse better (actual on iommu enabled systems).

aq_rx_refill_thres
----------------------------------------
Default value: 32
RX refill threshold. RX path will not refill freed descriptors until the
specified number of free descriptors is observed. Larger values may help
better page reuse but may lead to packet drops as well.


Config file parameters
=======================
Some parameters can be changed in the {source_dir}/aq_cfg.h file:

AQ_CFG_VECS_DEF
------------------------------------------------------------
Number of queues
Valid Range: 0 - 8 (up to AQ_CFG_VECS_MAX)
Default value: 8
Notice this value will be capped by the number of cores available on the system.

AQ_CFG_IS_RSS_DEF
------------------------------------------------------------
Enable/disable Receive Side Scaling

This feature allows the adapter to distribute receive processing
across multiple CPU-cores and to prevent from overloading a single CPU core.

Valid values
0 - disabled
1 - enabled

Default value: 1

AQ_CFG_NUM_RSS_QUEUES_DEF
------------------------------------------------------------
Number of queues for Receive Side Scaling
Valid Range: 0 - 8 (up to AQ_CFG_VECS_DEF)

Default value: AQ_CFG_VECS_DEF

AQ_CFG_IS_LRO_DEF
------------------------------------------------------------
Enable/disable Large Receive Offload

This offload enables the adapter to coalesce multiple TCP segments and indicate
them as a single coalesced unit to the OS networking subsystem.
The system consumes less energy but it also introduces more latency in packets
processing.

Valid values
0 - disabled
1 - enabled

Default value: 1

AQ_CFG_TX_CLEAN_BUDGET
----------------------------------------
Maximum descriptors to cleanup on TX at once.
Default value: 256

AQ_CFG_UDP_RSS_DISABLE
------------------------------------------------------------
Disable RSS for UDP traffic

Turning on workaround of HW bug by routing all UDP pakets through queue 0.

Valid values
0 - disabled
1 - enabled

Default value: 0

After the aq_cfg.h file changed the driver must be rebuilt to take effect.

Antigua Flashless boot support
==============================
Driver supports the loading of firmware from Host (instead of the flash).
The feature is useful in the case of flashless adapter or, when user wants to
load specific firmware than the one flashed on adapter.

Steps:
------
1. Copy the firmware binary in clx format to /lib/firmware/mrvl/04C0.clx path.
2. Supply values for below module parameters during the driver load,
	parm: aq_fw_did:Use FW image for this DID (array of uint)
	parm: aq_force_host_boot:Force host boot (array of uint)
   Example:
	insmod atlantic.ko aq_force_host_boot=1 aq_fw_did=0x04c0

Notes:
------
1. This is a driver load time feature. If user doesn't provide module parameters
   (mentioned above), driver tries to load the Firmware from flash.
2. When these module parameters are supplied, driver ignores firmware present on
   the flash i.e., if for some reason flashless boot fails then driver doesn't
   try the firmware load from flash.

Uninstall
=========================

To manually uninstall this driver:
------------------------------------------------------------
Run the following command:
	make uninstall
or:
	sudo rmmod atlantic
	sudo rm -f /lib/modules/`uname -r`/aquantia/atlantic.ko
	depmod -a `uname -r`

NB! You might need to update initramfs image on uninstall
(e.g. if atlantic.ko is a part of it, otherwise an old version will be
loaded from initramfs image on next reboot).
This is a potentially harmful operation, so 'make uninstall' will check
if such an update is needed and will ask for your consent before actually
running update-initramfs / dracut. Please make sure you understand the
risks before choosing 'Y'!
If you are running the commands yourself, then remember that
update-initramfs / dracut might be needed.

Uninstall driver with dkms
------------------------------------------------------------
Run the following command:
	sudo ./dkms.sh uninstall

Uninstall driver on Debian\Ubuntu using atlantic-x.y.z.deb
------------------------------------------------------------
Run the following command:
	sudo dpkg -P atlantic

Uninstall driver using atlantic-x.y.z.noarch.rpm
------------------------------------------------------------
Run the following command:
	sudo rpm -e atlantic-x.y.z.noarch

Support
=======

If an issue is identified with the released source code on the supported
kernel with a supported adapter, email the specific information related
to the issue to support@aquantia.com

License
=======

Atlantic Network Driver
Copyright (C) 2014-2019 aQuantia Corporation
Copyright (C) 2019-2020 Marvell International Ltd.

This program is free software; you can redistribute it and/or modify it
under the terms and conditions of the GNU General Public License,
version 2, as published by the Free Software Foundation.

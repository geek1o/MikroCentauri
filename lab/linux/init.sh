#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /run /tmp
mount -t devpts devpts /dev/pts
ip link set lo up
modprobe e1000
modprobe virtio_net
modprobe virtio_rng
role=client
address=192.168.88.10/24
gateway=192.168.88.1
alias_address=none
for item in $(cat /proc/cmdline); do
    case "$item" in
        mc.role=*) role=${item#*=} ;;
        mc.address=*) address=${item#*=} ;;
        mc.gateway=*) gateway=${item#*=} ;;
        mc.alias=*) alias_address=${item#*=} ;;
    esac
done
ip link set eth0 up
ip address add "$address" dev eth0
if [ "$alias_address" != none ]; then ip address add "$alias_address" dev eth0; fi
if [ "$gateway" != none ]; then ip route add default via "$gateway"; fi
echo 1 > /proc/sys/net/ipv6/conf/eth1/disable_ipv6
ip link set eth1 up
ip address add 10.0.2.15/24 dev eth1
echo "nameserver 192.168.88.1" > /etc/resolv.conf
if [ "$role" = client ]; then
    ip address add 192.168.88.20/24 dev eth0
    ip address add 192.168.88.30/24 dev eth0
else
    ip address add 203.0.113.20/24 dev eth0
fi
echo "MC_LAB_READY role=$role address=$address gateway=$gateway"
if [ -x /usr/bin/mc-lab ]; then
    if [ "$role" = server ]; then
        /usr/bin/mc-lab serve > /tmp/mc-lab.log 2>&1 &
    else
        /usr/bin/mc-lab client > /tmp/mc-lab.log 2>&1 &
    fi
fi
if [ "$role" = server ] && [ -x /lab/sing-box ] && [ -f /lab/server.json ]; then
    /lab/sing-box run -c /lab/server.json > /tmp/sing-box.log 2>&1 &
fi
if [ -x /lab/mc-quic ]; then
    if [ "$role" = server ]; then /lab/mc-quic serve > /tmp/quic.log 2>&1 &
    else /lab/mc-quic control > /tmp/quic.log 2>&1 &
    fi
fi
while true; do
    /bin/sh || true
done

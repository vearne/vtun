#!bin/bash

# set ulimit
echo "set ulimit"
echo "ulimit -SHn 1024000" >> /etc/profile
ulimit -n 1024000
echo "* soft nofile 1024000" >> /etc/security/limits.conf
echo "* hard nofile 1024000" >> /etc/security/limits.conf

# enable bbr
echo "enable bbr"
echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf

# enable ip forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl net.ipv4.tcp_available_congestion_control
sysctl -p

# show results
echo "results:"
ulimit -n
lsmod | grep bbr

echo "DONE!!!"

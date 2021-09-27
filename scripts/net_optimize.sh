#!bin/bash

# set ulimit
if grep -Eqi "ulimit -SHn" /etc/profile || grep -Eqi "* soft nofile|* hard nofile" /etc/security/limits.conf; then
        echo "ulimit has been optimized!"
else
        echo "ulimit -SHn 1024000" >> /etc/profile
        ulimit -n 1024000
        echo "* soft nofile 1024000" >> /etc/security/limits.conf
        echo "* hard nofile 1024000" >> /etc/security/limits.conf
fi

# enable bbr
if grep -Eqi "bbr" /etc/sysctl.conf; then
        echo "bbr has enabled!"
else
        echo "enable bbr"
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        sysctl net.ipv4.tcp_available_congestion_control
fi

# enable ip forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -p
# show results
echo "results:"
ulimit -n
lsmod | grep bbr

echo "DONE!!!"

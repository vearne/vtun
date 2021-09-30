#!bin/bash
#change your config
DOMAIN="your.domain"
PORT="443"
CIDR="172.16.0.235/24"
GATEWAY="192.168.1.1"
DEVICE="wlp36s0"
TUN="tun0"

echo "starting..."
IP=$(ping -c 1 $DOMAIN | gawk -F'[()]' '/PING/{print $2}')
echo $DOMAIN $IP

#start client
sudo killall vtun-linux-amd64
sudo ./bin/vtun-linux-amd64 -c $CIDR -s $DOMAIN:$PORT &
sleep 1

#routing all your traffic
sudo ip route add 0.0.0.0/1 dev $TUN
sudo ip route add 128.0.0.0/1 dev $TUN
sudo ip route delete $IP/32 via $GATEWAY dev $DEVICE
sudo ip route add $IP/32 via $GATEWAY dev $DEVICE

echo "show ip route"
sudo ip route

echo "STARTED!!!"

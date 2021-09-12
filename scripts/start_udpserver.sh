#!bin/bash

sudo killall vtun-linux-amd64
sudo ./bin/vtun-linux-amd64 -S -l=:3001 -c=172.16.0.1/24 -p=udp &
echo "STARTED!!!"

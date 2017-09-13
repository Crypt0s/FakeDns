#!/bin/bash
echo "Creating tun for user $1"
ip link delete tun0
ip tuntap add dev tun0 mode tun user $1 group $1
ip link set tun0 up
ip addr add 10.0.0.1/24 dev tun0
echo "DONE STAGE 1"

# iptables rules will look something like this
#-A FORWARD -i tun0 -p tcp --dport 3389 -d 192.168.0.0/24 -j ACCEPT

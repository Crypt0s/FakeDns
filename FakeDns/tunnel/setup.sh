#!/bin/bash
USR=`whoami`
echo "Creating tun for current user $USR -- you must run FakeDNS as this user."
ip link delete tun0 &> /dev/null
ip tuntap add dev tun0 mode tun user $USR group $USR
ip link set tun0 up
ip addr add 10.0.0.1/24 dev tun0
echo "DONE STAGE 1"

# iptables rules will look something like this
#-A FORWARD -i tun0 -p tcp --dport 3389 -d 192.168.0.0/24 -j ACCEPT
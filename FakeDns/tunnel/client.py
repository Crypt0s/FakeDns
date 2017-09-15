#!/usr/bin/python
import socket
import sys
sys.path.append("../")
import FakeDns
import base64

# This script expels packets from the tunnel into your network via tun iface

# process packets
def process(dns_packet):
    packet = FakeDns.DNSQuery_old
    data = packet(dns_packet).domain
    data = data.translate(None,".")
    data = base64.b64decode(data)

    # OK At this stage we have a binary packet and need it to exit the tunnel *somehow*
    print data.encode("hex")



if __name__ == "__main__":
    # create a UDP socket on all interfaces on port 53
    sock_in = socket.socket(socket.AF_INET,type=socket.SOCK_DGRAM)
    sock_in.bind(("0.0.0.0", 53))

    while True:
        data, addr = sock_in.recvfrom(1024)
        process(data)

import time
import fcntl
import os
import struct
import subprocess
import socket
import sys
import random

# add the fakedns top level directory to the current python import pathlist
sys.path.append("../")
import FakeDns

# transaction id    query type     questions     Answer RRs  Authority RR    additional rrs   ????  query     end   type  class
#      xx xx         0x0100         00001          0000        0000             0000           02  [x-250]    00    0001  0001
#     random         Standard       normal                                                                

class TypeNotFound(Exception):
    def __init__(self, msg):
        self.message = msg
        print msg


def get_type(type_txt):
    for code, type in FakeDns.TYPE.iteritems():
        if type_txt == type:
            return code
    raise TypeNotFound("opcode for %s not found" % type_txt)


# build a great DNS request packet.
class DNSQuery:
    def __init__(self, domain, type):
        # parse the domain and replace subdomain dots with \x09, tld with 03

        # develop a random id
        self.txid = struct.pack("H", random.randint(0, 0xffff))

        # TODO: allow these flags to be set by user call to dnsquery class
        self.flags = struct.pack(">H",0b0000000100000000)

        self.numquestions = struct.pack(">H", 0x0001)

        self.ansrr = '\x00\x00'
        self.authrr = '\x00\x00'
        self.addrr = '\x00\x00'

        self.domain = ""
        for label in domain.split('.'):
            label_length = struct.pack(">B", len(label))
            self.domain += label_length + label

        # convert type to opcode
        self.type = get_type(type)

        self.req_class = "\x00\x01"

    # build the packet
    @property
    def packet(self):
        return self.txid + self.flags + self.numquestions + self.ansrr + self.authrr + self.addrr + self.domain + self.type + self.req_class


# Bring it up and assign addresses.
# subprocess.check_call('ifconfig tun0 192.168.7.1 pointopoint 192.168.7.2 up',
#        shell=True)

def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.ntohs(struct.unpack('H', s[10:12])[0])
    d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4 * (d['header_len'] - 5)]
    else:
        d['options'] = None
    d['data'] = s[4 * d['header_len']:]
    return d


def print_packet(pktlen, data, timestamp):
    print "hi"
    global destination
    global sock_out
    global addr
    if not data:
        return

    # TODO: this will create == to pad text and is not RFC-valid but will still pass to server

    # outbound will be a [][]
    outbound = []
    data = base64.b64encode(data)
    # TODO: Set some flag in the DNS packet to indicate that we are transmitting a fragmented packet
    # TODO: Fragmented packets could arrive out-of-order, add a flag value to handle fragmented packets
    # TODO: Decide if handling fragmented packets is worth wrapping in a custom protocol or not instead of
    # abusing the DNS spec as this may cause this to be findable by Snort.

    # MAXLEN of entire record
    MAX_RECORD = 250

    # maxlen of label
    LABEL_MAX = 63

    # break up the data into labels and records of appropriate size and fragment into multiple querys if needed
    if len(data) > LABEL_MAX:
        print "We'll have to fragment this"
        for i in xrange(0, len(data), MAX_RECORD):
            tmp_record = data[i:i + MAX_RECORD]
            tmp_qry = ""
            for x in xrange(0,len(tmp_record), LABEL_MAX):
                label = tmp_record[x:x + LABEL_MAX]
                tmp_qry += label + "."
            outbound.append(tmp_qry)

    # later on all the .'s will get translated to proper labels.
    else:
        outbound.append(base64.b64encode(data))

    for fragment in outbound:

        # build query off of template
        #def __init__(self, domain, type):
        query = DNSQuery(fragment,"A")

        # handle outbound packets
        sock_out.sendto(query.packet, addr)

        # OK The whole packet is broken into 250-byte chunks of base64, we can now feed the packet into DNS requests
        # we just broke up the entire packet though - so layers 3-7 will need to be broken out on the other end.


    # if data[12:14]=='\x08\x00':
    else:
        decoded = decode_ip_packet(data[14:])
        print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                                 time.localtime(timestamp)),
                                   timestamp % 60,
                                   decoded['source_address'],
                                   decoded['destination_address'])
        for key in ['version', 'header_len', 'tos', 'total_len', 'id', 'flags', 'fragment_offset', 'ttl']:
            print '  %s: %d' % (key, decoded[key])
        # print '  protocol: %s' % protocols[decoded['protocol']]
        print '  header checksum: %d' % decoded['checksum']
        print '  data: %s' % decoded['data'].encode("hex")


if __name__ == "__main__":
    # Some constants used to ioctl the device file. I got them by a simple C
    # program.
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    # Open file corresponding to the TUN device.
    tun = open('/dev/net/tun', 'r+b')
    ifr = struct.pack('16sH', 'tun0', IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    fcntl.ioctl(tun, TUNSETOWNER, 1000)

    import base64
    import pcap
    import pdb

    import ConfigParser

    conf = ConfigParser.ConfigParser()
    conf.read("tunnel.conf")

    #destination = conf.get("SERVER", "destip")

    sock_out = socket.socket(type=socket.SOCK_DGRAM)
    addr = ('%s' % (conf.get("SERVER","destip")), conf.getint("SERVER","destport"))

    # pdb.set_trace()
    p_obj = pcap.pcapObject()
    p_obj.open_live("tun0", 1600, 0, 100)

    while True:
        # Read an IP packet been sent to this TUN device.
        # packet = os.read(tun.fileno(), 2048)
        p_obj.dispatch(1, print_packet)

        ## Write the reply packet into TUN device.
        # os.write(tun.fileno(), ''.join(packet))

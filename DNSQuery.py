#!/usr/bin/python
import pdb
import os
from fakedns import TYPE

"""
Makes massive DNS requests in order to exfil dox, bruh.
Bitbang all the way to the BANK

Transact ID     Flags   Questions   Answer RR   Authority RR's  Additional RRs  len  record  len  record  ect... END  TYPE   class
   00 00        01 00     00 01       00 00         00 00           00 00        00    --     00    --           00   00 00   00 01 (in)
             (std query)
"""

class DNSQuery:

    class BadQuery(Exception):
        pass

    # Handle making a DNSQuery out of a raw request for various reasons
    @staticmethod
    def parse(raw_query):
        def readrecord(recordsection):
            recordsection = buffer(recordsection)
            section_length = None
            placeholder = 0
            domain_name = ''

            while section_length != 0:     # 00 is the length of the 'root' label
                section_length = ord(recordsection[placeholder])
                label = recordsection[placeholder+1:placeholder+section_length+1] # Python list splicing - add one to the end.
                placeholder = placeholder + section_length+1
                if domain_name != '' and ord(recordsection[placeholder]) != "\x00":
                    domain_name += '.' + label
                else:
                    domain_name += label

            # ok we found the end of the last label -- we can parse the next 4 bytes as type and class
            type = recordsection[placeholder:placeholder+2]
            dns_class = recordsection[placeholder+2:placeholder+4]
            return (domain_name,type,dns_class)

        # until I know better about the resource records, I will assume that the query starts on byte 13
        # TODO: Error handling
        (domain_name,type,dns_class) = readrecord(raw_query[12:])

        dns_kwargs = {
            'transact_id' : raw_query[0:2], # Easy 2-byte values
            'flags' : raw_query[2:4],       # ''
            'questions' : raw_query[4:6],   # ''
            'answer_rrs' : raw_query[6:8],  # Gets a little more complicated here
            'auth_rrs' : raw_query[8:10],   # I dont have to handle this right now
            'add_rrs' : raw_query[10:12],   #
            'dns_class' : dns_class,
            'type' : type,
            'query' : domain_name,          # That I have to do this is dumb but...
            'domain_name': domain_name
        }
        # TODO: Error handling
        return DNSQuery(**dns_kwargs)

    def __init__(self, **kwargs):
        # Let you shoot yourself in the foot but babysit enough where you won't be dysfunctional...
        self.transact_id = os.urandom(2) if not kwargs.has_key("transact_id") else kwargs["transact_id"]# note that this should be crypto-random because reasons
        self.flags = "\x01\x00" if not kwargs.has_key("flags") else kwargs["flags"]                     # Normal Query
        self.questions = "\x00\x01" if not kwargs.has_key("questions") else kwargs["questions"]
        self.answer_rrs = "\x00\x00" if not kwargs.has_key("answer_rrs") else kwargs["answer_rrs"]
        self.auth_rrs = "\x00\x00" if not kwargs.has_key("auth_rrs") else kwargs["auth_rrs"]            # things
        self.add_rrs = "\x00\x00" if not kwargs.has_key("add_rrs") else kwargs["add_rrs"]

        # optional override -- there's a better kwargs-to-attr pattern i will come back and implement later
        if kwargs.has_key('domain_name'):
            self.domain_name = kwargs['domain_name']

        # This is the one thing you HAVE to provide
        if not kwargs.has_key('query'):
            raise(BadQuery)
        else:
            self._make_request(kwargs['query'])

        self.type = "\x00\x01" if not kwargs.has_key("type") else kwargs["type"]                        # A record
        self.dns_class = "\x00\x01" if not kwargs.has_key("dns_class") else kwargs["dns_class"]         # IN Class...like I am not.

        # OK Build me a packet now.
        self._build_packet()

    # supports special-char domain name requests...
    def _make_request(self, data):
        request = ""
        for part in data.encode('idna').split('.'): # idna encoding is (apparently) the best, handles non-specials well.
            request += chr(len(part))
            request += part
        request += "\x00"                      # Add the "root" entry of null chr
        self.query = request

    def _build_packet(self):
        self.packet = self.transact_id + self.flags + self.questions + self.answer_rrs + self.auth_rrs + self.add_rrs + self.query + self.type + self.dns_class

    # TODO: Pretty Pretty Printing!
    def __str__(self):
        pass

if __name__ == "__main__":
    """
    Important Note:

    http://serverfault.com/questions/404840/when-do-dns-queries-use-tcp-instead-of-udp
    DNS goes over TCP when the size of the request or the response is greater than a single packet...
    The maximum size was originally 512 bytes but there is an extension to the DNS protocol that allows clients to indicate that they can handle UDP responses of up to 4096 bytes.
    """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#SOCK_STREAM)
    #s.connect(('8.8.8.8', 53))

    # TODO: Some logic that determines if we need TCP for this request.
    myquery = DNSQuery(query="google.com").packet

    pdb.set_trace()
    DNSQuery.parse(myquery)

    sent = s.sendto(myquery,('8.8.8.8', 53))

    print "Bytes Launched Into CyberSpace: " + str(sent)
    response = s.recv(512)
    s.close()

    print "Got: " + str(len(response)) + " Bytes back."

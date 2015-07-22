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

    def __init__(self, **kwargs):
        # Let you shoot yourself in the foot but babysit enough where you won't be dysfunctional...
        self.transact_id = os.urandom(4) if not kwargs.has_key("transact_id") else kwargs["transact_id"]# note that this should be crypto-random because reasons
        self.flags = "\x01\x00" if not kwargs.has_key("flags") else kwargs["flags"]                     # Normal Query
        self.questions = "\x00\x01" if not kwargs.has_key("questions") else kwargs["questions"]
        self.answer_rrs = "\x00\x00" if not kwargs.has_key("answer_rrs") else kwargs["answer_rrs"]
        self.auth_rrs = "\x00\x00" if not kwargs.has_key("auth_rrs") else kwargs["auth_rrs"]            # things
        self.add_rrs = "\x00\x00" if not kwargs.has_key("add_rrs") else kwargs["add_rrs"]

        # This is the one thing you HAVE to provide
        if not kwargs.has_key('query'):
            raise(BadQuery)
        else:
            self.query = self._make_request(kwargs['query'])

        self.type = "\x00\x01" if not kwargs.has_key("type") else kwargs["type"]                        # A record
        self.dns_class = "\x00\x01" if not kwargs.has_key("dns_class") else kwargs["dns_class"]         # IN Class...like I am not.

        # OK Build me a packet now.
        self.packet = self._build_packet()

    # supports special-char domain name requests...
    def _make_request(data):
        self.request = ""
        for part in data.encode('idna').split('.'): # idna encoding is (apparently) the best, handles non-specials well.
            self.request += chr(len(part))
            self.request += part
        self.request += "\x00"                      # Add the "root" entry of null chr

    def build_packet(self):
        self.packet = self.transact_id +
                        self.flags +
                        self.questions +
                        self.answer_rrs +
                        self.auth_rrs +
                        self.add_rrs +
                        self.query +
                        self.type +
                        self.dns_class

if __name__ == "__main__":
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((8.8.8.8, 53))

    myquery = DNSQuery(query="google.com").packet

    sent = s.send(myquery)

    print "Bytes Launched Into CyberSpace: " + str(sent)
    response = s.recv(512)
    s.close()

    print "Got:" + response

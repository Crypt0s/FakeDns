#!/usr/bin/env python
"""Fakedns.py: A regular-expression based DNS MITM Server by Crypt0s."""

import random
import struct
import socket


# Because python doesn't have native ENUM in 2.7:
# https://en.wikipedia.org/wiki/List_of_DNS_record_types
TYPE = {
    "\x00\x01": "A",
    "\x00\x1c": "AAAA",
    "\x00\x05": "CNAME",
    "\x00\x0c": "PTR",
    "\x00\x10": "TXT",
    "\x00\x0f": "MX",
    "\x00\x06": "SOA"
}



class DNSQuery_old:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        tipo = (ord(data[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.domain += data[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1  # you can implement CNAME and PTR
                lon = ord(data[ini])
            self.type = data[ini:][1:3]
        else:
            self.type = data[-4:-2]

class DNSQuery:

    class TypeNotFound(Exception):
        def __init__(self, msg):
            self.message = msg
            print msg

    def __init__(self, domain, type):
        # parse the domain and replace subdomain dots with \x09, tld with 03

        # develop a random id
        self.txid = struct.pack("H", random.randint(0, 0xffff))

        # TODO: allow these flags to be set by user call to dnsquery class
        self.flags = struct.pack(">H", 0b0000000100000000)

        self.numquestions = struct.pack(">H", 0x0001)

        self.ansrr = '\x00\x00'
        self.authrr = '\x00\x00'
        self.addrr = '\x00\x00'

        self.domain = ""
        for label in domain.split('.'):
            label_length = struct.pack(">B", len(label))
            self.domain += label_length + label

        # convert type to opcode
        self.type = self.get_type(type)

        self.req_class = "\x00\x01"

    def get_type(self, type_txt):
        for code, type in TYPE.iteritems():
            if type_txt == type:
                return code
        raise DNSQuery.TypeNotFound("opcode for %s not found" % type_txt)

    # build the packet
    @property
    def packet(self):
        return self.txid + self.flags + self.numquestions + self.ansrr + self.authrr + self.addrr + self.domain + self.type + self.req_class


# Stolen:
# https://github.com/learningequality/ka-lite/blob/master/python-packages/django/utils/ipv6.py#L209
def _is_shorthand_ip(ip_str):
    """Determine if the address is shortened.
    Args:
        ip_str: A string, the IPv6 address.
    Returns:
        A boolean, True if the address is shortened.
    """
    if ip_str.count('::') == 1:
        return True
    if any(len(x) < 4 for x in ip_str.split(':')):
        return True
    return False

# Stolen:
# https://github.com/learningequality/ka-lite/blob/master/python-packages/django/utils/ipv6.py#L209
def _explode_shorthand_ip_string(ip_str):
    """
    Expand a shortened IPv6 address.
    Args:
        ip_str: A string, the IPv6 address.
    Returns:
        A string, the expanded IPv6 address.
    """
    if not _is_shorthand_ip(ip_str):
        # We've already got a longhand ip_str.
        return ip_str

    hextet = ip_str.split('::')

    # If there is a ::, we need to expand it with zeroes
    # to get to 8 hextets - unless there is a dot in the last hextet,
    # meaning we're doing v4-mapping
    if '.' in ip_str.split(':')[-1]:
        fill_to = 7
    else:
        fill_to = 8

    if len(hextet) > 1:
        sep = len(hextet[0].split(':')) + len(hextet[1].split(':'))
        new_ip = hextet[0].split(':')

        for _ in xrange(fill_to - sep):
            new_ip.append('0000')
        new_ip += hextet[1].split(':')

    else:
        new_ip = ip_str.split(':')

    # Now need to make sure every hextet is 4 lower case characters.
    # If a hextet is < 4 characters, we've got missing leading 0's.
    ret_ip = []
    for hextet in new_ip:
        ret_ip.append(('0' * (4 - len(hextet)) + hextet).lower())
    return ':'.join(ret_ip)


class DNSResponse(object):
    def __init__(self, query):
        self.id = query.data[:2]  # Use the ID from the request.
        self.flags = "\x81\x80"  # No errors, we never have those.
        self.questions = query.data[4:6]  # Number of questions asked...
        # Answer RRs (Answer resource records contained in response) 1 for now.
        self.rranswers = "\x00\x01"
        self.rrauthority = "\x00\x00"  # Same but for authority
        self.rradditional = "\x00\x00"  # Same but for additionals.
        # Include the question section
        self.query = self._get_question_section(query)
        # The pointer to the resource record - seems to always be this value.
        self.pointer = "\xc0\x0c"
        # This value is set by the subclass and is defined in TYPE dict.
        self.type = None
        self.dnsclass = "\x00\x01"  # "IN" class.
        # TODO: Make this adjustable - 1 is good for noobs/testers
        self.ttl = "\x00\x00\x00\x01"
        # Set by subclass because is variable except in A/AAAA records.
        self.length = None
        self.data = None  # Same as above.

    def _get_question_section(self, query):
        # Query format is as follows: 12 byte header, question section (comprised
        # of arbitrary-length name, 2 byte type, 2 byte class), followed by an
        # additional section sometimes. (e.g. OPT record for DNSSEC)
        start_idx = 12
        end_idx = start_idx

        num_questions = (ord(query.data[4]) << 8) | ord(query.data[5])

        while num_questions > 0:
            while query.data[end_idx] != '\0':
                end_idx += ord(query.data[end_idx]) + 1
            # Include the null byte, type, and class
            end_idx += 5
            num_questions -= 1
        return query.data[start_idx:end_idx]

    def make_packet(self):
        try:
            return self.id + self.flags + self.questions + self.rranswers + \
                self.rrauthority + self.rradditional + self.query + \
                self.pointer + self.type + self.dnsclass + self.ttl + \
                self.length + self.data
        except (TypeError, ValueError):
            pass

    # allow calls to packet as if it were a property
    @property
    def packet(self):
        return self.make_packet()

    # allow a user to parse an inbound DNSResponse
    @staticmethod
    def parse(data):
        # NOT IMPLEMENTED YET
        return None


# All classes need to set type, length, and data fields of the DNS Response
# Finished
class A(DNSResponse):
    def __init__(self, query, record):
        super(A, self).__init__(query)
        self.type = "\x00\x01"
        self.length = "\x00\x04"
        self.data = self.get_ip(record)

    @staticmethod
    def get_ip(dns_record):
        ip = dns_record
        # Convert to hex
        return ''.join(chr(int(x)) for x in ip.split('.'))

# Implemented
class AAAA(DNSResponse):
    def __init__(self, query, address):
        super(AAAA, self).__init__(query)
        self.type = "\x00\x1c"
        self.length = "\x00\x10"
        # Address is already encoded properly for the response at rule-builder
        self.data = address

    # Thanks, stackexchange!
    # http://stackoverflow.com/questions/16276913/reliably-get-ipv6-address-in-python
    def get_ip_6(host, port=0):
        # search only for the wanted v6 addresses
        result = socket.getaddrinfo(host, port, socket.AF_INET6)
        # Will need something that looks like this:
        # just returns the first answer and only the address
        ip = result[0][4][0]

# Not yet implemented
class CNAME(DNSResponse):
    def __init__(self, query):
        super(CNAME, self).__init__(query)
        self.type = "\x00\x05"

# Implemented
class PTR(DNSResponse):
    def __init__(self, query, ptr_entry):
        super(PTR, self).__init__(query)
        self.type = "\x00\x0c"
        self.ttl = "\x00\x00\x00\x00"
        ptr_split = ptr_entry.split('.')
        ptr_entry = "\x07".join(ptr_split)

        self.data = "\x09" + ptr_entry + "\x00"
        self.length = chr(len(ptr_entry) + 2)
        # Again, must be 2-byte value.
        if self.length < '\xff':
            self.length = "\x00" + self.length

# Finished
class TXT(DNSResponse):
    def __init__(self, query, txt_record):
        super(TXT, self).__init__(query)
        self.type = "\x00\x10"
        self.data = txt_record
        self.length = chr(len(txt_record) + 1)
        # Must be two bytes.
        if self.length < '\xff':
            self.length = "\x00" + self.length
        # Then, we have to add the TXT record length field!  We utilize the
        # length field for this since it is already in the right spot
        self.length += chr(len(txt_record))


# Technically this is a subclass of A
class NONEFOUND(DNSResponse):
    def __init__(self, query):
        super(NONEFOUND, self).__init__(query)
        self.type = query.type
        self.flags = "\x81\x83"
        self.rranswers = "\x00\x00"
        self.length = "\x00\x00"
        self.data = "\x00"
        print ">> Built NONEFOUND response"

# And this one is because Python doesn't have Case/Switch
CASE = {
    "\x00\x01": A,
    "\x00\x1c": AAAA,
    "\x00\x05": CNAME,
    "\x00\x0c": PTR,
    "\x00\x10": TXT
}
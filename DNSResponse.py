#!/usr/bin/python
"""
This file contains the classes for DNS Responses
"""
class DNSResponse(object):

    def __init__(self, query):
        self.id = query.data[:2]        # Use the ID from the request.
        self.flags = "\x81\x80"         # No errors, we never have those.
        self.questions = query.data[4:6]  # Number of questions asked...
        # Answer RRs (Answer resource records contained in response) 1 for now.
        self.rranswers = "\x00\x01"
        self.rrauthority = "\x00\x00"   # Same but for authority
        self.rradditional = "\x00\x00"  # Same but for additionals.
        # Include the question section
        self.query = self._get_question_section(query)
        # The pointer to the resource record - seems to always be this value.
        self.pointer = "\xc0\x0c"
        # This value is set by the subclass and is defined in TYPE dict.
        self.type = None
        self.dnsclass = "\x00\x01"      # "IN" class.
        # TODO: Make this adjustable - 1 is good for noobs/testers
        self.ttl = "\x00\x00\x00\x01"
        # Set by subclass because is variable except in A/AAAA records.
        self.length = None
        self.data = None                # Same as above.


    def _get_question_section(self,query):
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
            self.packet = self.id + self.flags + self.questions + self.rranswers + self.rrauthority + \
                self.rradditional + self.query + self.pointer + self.type + \
                self.dnsclass + self.ttl + self.length + self.data
        except:
            pdb.set_trace()
        return self.packet

# All classess need to set type, length, and data fields of the DNS Response
# Finished


class A(DNSResponse):

    def __init__(self, query, record):
        super(A, self).__init__(query)
        self.type = "\x00\x01"
        self.length = "\x00\x04"
        self.data = self.get_ip(record, query)

    def get_ip(self, dns_record, query):
        ip = dns_record
        # Convert to hex
        return str.join('', map(lambda x: chr(int(x)), ip.split('.')))

# Not implemented, need to get ipv6 to translate correctly into hex


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

# Not yet implemented


class PTR(DNSResponse):

    def __init__(self, query, ptr_entry):
        super(PTR, self).__init__(query)
        self.type = "\x00\x0c"

        ptr_split = ptr_entry.split('.')
        ptr_entry = "\x07".join(ptr_split)

        self.data = "\x0e" + ptr_entry + "\x00"
        self.data = "\x132-8-8-8\x02lulz\x07com\x00"
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
        self.length = self.length + chr(len(txt_record))

# And these are because Python doesn't have Case/Switch
TYPE = {
    "\x00\x01": "A",
    "\x00\x1c": "AAAA",
    "\x00\x05": "CNAME",
    "\x00\x0c": "PTR",
    "\x00\x10": "TXT",
    "\x00\x0f": "MX"
}

CASE = {
    "\x00\x01": A,
    "\x00\x1c": AAAA,
    "\x00\x05": CNAME,
    "\x00\x0c": PTR,
    "\x00\x10": TXT
}

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

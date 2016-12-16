#!/usr/bin/env python
"""Fakedns.py: A regular-expression based DNS MITM Server by Crypt0s."""

import pdb
import socket
import re
import sys
import os
import SocketServer
import signal
import argparse

# inspired from DNSChef
class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, server_address, request_handler):
        self.address_family = socket.AF_INET
        SocketServer.UDPServer.__init__(
            self, server_address, request_handler)


class UDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        (data, s) = self.request
        respond(data, self.client_address, s)


class DNSQuery:
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

# Because python doesn't have native ENUM in 2.7:
# https://en.wikipedia.org/wiki/List_of_DNS_record_types
TYPE = {
    "\x00\x01": "A",
    "\x00\x1c": "AAAA",
    "\x00\x05": "CNAME",
    "\x00\x0c": "PTR",
    "\x00\x10": "TXT",
    "\x00\x0f": "MX",
    "\x00\x06":"SOA"
}

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


def _get_question_section(query):
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
        self.query = _get_question_section(query)
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

    def make_packet(self):
        try:
            return self.id + self.flags + self.questions + self.rranswers + \
                self.rrauthority + self.rradditional + self.query + \
                self.pointer + self.type + self.dnsclass + self.ttl + \
                self.length + self.data
        except (TypeError, ValueError):
            pass

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

# And this one is because Python doesn't have Case/Switch
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


class Rule (object):
    def __init__(self, rule_type, domain, ips, rebinds, threshold):
        self.type = rule_type
        self.domain = domain
        self.ips = ips
        self.rebinds = rebinds
        self.rebind_threshold = threshold

        # we need an additional object to track the rebind rules
        if self.rebinds is not None:
            self.match_history = {}
            self.rebinds = self._round_robin(rebinds)
        self.ips = self._round_robin(ips)

    def _round_robin(self, ip_list):
        """
        Creates a generator over a list modulo list length to equally move between all elements in the list each request
        Since we have rules broken out into objects now, we can have this without much overhead.
        """
        # check to make sure we don't try to modulo by zero
        # if we would, just add the same element to the list again.
        if len(ip_list) == 1:
            ip_list.append(ip_list[0])

        # should be fine to continue now.
        index = 0
        while 1: # never stop iterating - it's OK since we dont always run
            yield ip_list[index]
            index += 1
            index = index % len(ip_list)

    def match(self, req_type, domain, addr):
        # assert that the query type and domain match

        try:
            req_type = TYPE[req_type]
        except KeyError:
            return None

        try:
            assert self.type == req_type
        except AssertionError:
            return None

        try:
            assert self.domain.match(domain)
        except AssertionError:
            return None

        # Check to see if we have a rebind rule and if we do, return that addr first
        if self.rebinds:
            if self.match_history.has_key(addr):

                # passed the threshold - start doing a rebind
                if self.match_history[addr] >= self.rebind_threshold:
                    return self.rebinds.next()

                # plus one
                else:
                    self.match_history[addr] += 1

            # add new client to this match history
            else:
                self.match_history[addr] = 1

        # We didn't trip on any rebind rules (or didnt have any)
        # but we're returning a rule-based entry based on the match
        return self.ips.next()


# Error classes for handling rule issues
class RuleError_BadRegularExpression(Exception):
    def __init__(self,lineno):
        print "\n!! Malformed Regular Expression on rulefile line #%d\n\n" % lineno


class RuleError_BadRuleType(Exception):
    def __init__(self,lineno):
        print "\n!! Rule type unsupported on rulefile line #%d\n\n" % lineno


class RuleError_BadFormat(Exception):
    def __init__(self,lineno):
        print "\n!! Not Enough Parameters for rule on rulefile line #%d\n\n" % lineno


class RuleEngine2:

    # replaces the self keyword, but could be expanded to any keyword replacement
    def _replace_self(self, ips):
        # Deal with the user putting "self" in a rule (helpful if you don't know your IP)
        for ip in ips:
            if ip.lower() == 'self':
                try:
                    self_ip = socket.gethostbyname(socket.gethostname())
                except socket.error:
                    print ">> Could not get your IP address from your " \
                          "DNS Server."
                    self_ip = '127.0.0.1'
                ips[ips.index(ip)] = self_ip
        return ips


    def __init__(self, file_):
        """
        Parses the DNS Rulefile, validates the rules, replaces keywords

        """

        # track DNS requests here
        self.match_history = {}

        self.rule_list = []

        # A lol.com IP1,IP2,IP3,IP4,IP5,IP6 rebind_threshold%Rebind_IP1,Rebind_IP2
        with open(file_, 'r') as rulefile:
            rules = rulefile.readlines()
            lineno = 0 # keep track of line number for errors

            for rule in rules:

                # ignore blank lines or lines starting with hashmark (coments)
                if rule == "" or rule.lstrip()[0] == "#" or rule == '\n':
                    # thank you to github user cambid for the comments suggestion
                    continue

                # Confirm that the rule has at least three columns to it
                if len(rule.split()) < 3:
                    raise RuleError_BadFormat(lineno)

                # break the rule out into its components
                s_rule = rule.split()
                rule_type = s_rule[0].upper()
                domain = s_rule[1]
                ips = s_rule[2].split(',') # allow multiple ip's thru commas

                # only try this if the rule is long enough
                if len(s_rule) == 4:
                    rebinds = s_rule[3]
                    # handle old rule style (maybe someone updated)
                    if '%' in rebinds:
                        rebind_threshold,rebinds = rebinds.split('%')
                        rebinds = rebinds.split(',')
                        rebind_threshold = int(rebind_threshold)
                    else:
                        # in the old days we assumed a rebind thresh of 1
                        rebind_threshold = 1
                else:
                    rebinds = None
                    rebind_threshold = None

                # Validate the rule
                # make sure we understand this type of response
                if rule_type not in TYPE.values():
                    raise RuleError_BadRuleType(lineno)
                # attempt to parse the regex (if any) in the domain field
                try:
                    domain = re.compile(domain)
                except:
                    raise RuleError_BadRegularExpression(lineno)

                # replace self in the list of ips and list of rebinds (if any)
                ips = self._replace_self(ips)
                if rebinds is not None:
                    rebinds = self._replace_self(rebinds)

                # Deal With Special IPv6 Nonsense
                if rule_type.upper() == "AAAA":
                    tmp_ip_array = []
                    for ip in ips:
                        if _is_shorthand_ip(ip):
                            ip = _explode_shorthand_ip_string(ip)

                        ip = ip.replace(":", "").decode('hex')
                        tmp_ip_array.append(ip)
                    ips = tmp_ip_array


                # add the validated and parsed rule into our list of rules
                self.rule_list.append(Rule(rule_type, domain, ips, rebinds, rebind_threshold))

                # increment the line number
                lineno += 1

            print ">> Parsed %d rules from %s" % (len(self.rule_list),file_)


    def match(self, query, addr):
        """
        See if the request matches any rules in the rule list by calling the
        match function of each rule in the list

        The rule checks two things before it continues so I imagine this is
        probably still fast

        """
        for rule in self.rule_list:
            result = rule.match(query.type, query.domain, addr)
            if result is not None:
                response_data = result

                # Return Nonefound if the rule says "none"
                if response_data.lower() == 'none':
                    return NONEFOUND(query).make_packet()

                response = CASE[query.type](query, response_data)

                print ">> Matched Request - " + query.domain
                return response.make_packet()

        # if we got here, we didn't match.
        # Forward a request that we didnt have a rule for to someone else

        # if the user said not to forward requests, and we are here, it's time to send a NONEFOUND
        if args.noforward:
            print ">> Don't Forward %s" % query.domain
            return NONEFOUND(query).make_packet()
        try:
            s = socket.socket(type=socket.SOCK_DGRAM)
            s.settimeout(3.0)
            addr = ('%s' % (args.dns), 53)
            s.sendto(query.data, addr)
            data = s.recv(1024)
            s.close()
            print "Unmatched Request " + query.domain
            return data
        except socket.error, e:
            # We shouldn't wind up here but if we do, don't drop the request
            # send the client *something*
            print ">> Error was handled by sending NONEFOUND"
            print e
            return NONEFOUND(query).make_packet()


# Convenience method for threading.
def respond(data, addr, s):
    p = DNSQuery(data)
    response = rules.match(p, addr[0])
    s.sendto(response, addr)
    return response

# Capture Control-C and handle here
def signal_handler(signal, frame):
    print 'Exiting...'
    sys.exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='FakeDNS - A Python DNS Server')
    parser.add_argument(
        '-c', dest='path', action='store', required=True,
        help='Path to configuration file')
    parser.add_argument(
        '-i', dest='iface', action='store', default='0.0.0.0', required=False,
        help='IP address you wish to run FakeDns with - default all')
    parser.add_argument(
        '-p', dest='port', action='store', default=53, required=False,
        help='Port number you wish to run FakeDns')
    parser.add_argument(
        '--rebind', dest='rebind', action='store_true', required=False,
        default=False, help="Enable DNS rebinding attacks - responds with one "
        "result the first request, and another result on subsequent requests")
    parser.add_argument(
        '--dns', dest='dns', action='store', default='8.8.8.8', required=False,
        help='IP address of the upstream dns server - default 8.8.8.8'
    )
    parser.add_argument(
        '--noforward', dest='noforward', action='store_true', default=False, required=False,
        help='Sets if FakeDNS should forward any non-matching requests'
    )

    args = parser.parse_args()

    # Default config file path.
    path = args.path
    if not os.path.isfile(path):
        print '>> Please create a "dns.conf" file or specify a config path: ' \
              './fakedns.py [configfile]'
        exit()

    rules = RuleEngine2(path)
    rule_list = rules.rule_list

    interface = args.iface
    port = args.port

    try:
        server = ThreadedUDPServer((interface, int(port)), UDPHandler)
    except socket.error:
        print ">> Could not start server -- is another program on udp:{0}?".format(port)
        exit(1)

    server.daemon = True

    # Tell python what happens if someone presses ctrl-C
    signal.signal(signal.SIGINT, signal_handler)
    server.serve_forever()
    server_thread.join()

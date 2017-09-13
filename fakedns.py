#!/usr/bin/python

try:
    import FakeDns
except:
    print "Could not import FakeDns - was the server file moved without installing FakeDns?"

# TODO: DO I want to have the server implemented as a separate file? I say yes.

import signal
import argparse
import os
import sys
import socket
import SocketServer
from FakeDns import *
import re

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
            lineno = 0  # keep track of line number for errors

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
                ips = s_rule[2].split(',')  # allow multiple ip's thru commas

                # only try this if the rule is long enough
                if len(s_rule) == 4:
                    rebinds = s_rule[3]
                    # handle old rule style (maybe someone updated)
                    if '%' in rebinds:
                        rebind_threshold, rebinds = rebinds.split('%')
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
                    raise RuleError_BadRuleType(lineno+1)
                # attempt to parse the regex (if any) in the domain field
                try:
                    domain = re.compile(domain)
                except:
                    raise RuleError_BadRegularExpression(lineno+1)

                # replace self in the list of ips and list of rebinds (if any)
                ips = self._replace_self(ips)
                if rebinds is not None:
                    rebinds = self._replace_self(rebinds)

                # Deal With Special IPv6 Nonsense
                if rule_type.upper() == "AAAA":
                    tmp_ip_array = []
                    for ip in ips:
                        if FakeDns._is_shorthand_ip(ip):
                            ip = FakeDns._explode_shorthand_ip_string(ip)

                        ip = ip.replace(":", "").decode('hex')
                        tmp_ip_array.append(ip)
                    ips = tmp_ip_array

                # add the validated and parsed rule into our list of rules
                self.rule_list.append(Rule(rule_type, domain, ips, rebinds, rebind_threshold))

                # increment the line number
                lineno += 1

            print ">> Parsed %d rules from %s" % (len(self.rule_list), file_)

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
    p = DNSQuery_old(data)
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
        exit(1)

    rules = RuleEngine2(path)
    rule_list = rules.rule_list

    interface = args.iface
    port = args.port

    try:
        server = ThreadedUDPServer((interface, int(port)), UDPHandler)
        server.daemon = True
    except socket.error:
        print ">> Could not start server -- is another program on udp:{0}?".format(port)
        exit(1)

    # Tell python what happens if someone presses ctrl-C
    signal.signal(signal.SIGINT, signal_handler)
    server.serve_forever()


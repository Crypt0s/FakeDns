#!/usr/bin/python
"""													"""
"""                    Fakedns.py					"""
"""    A regular-expression based DNS MITM Server	"""
"""						by: Crypt0s					"""

import pdb
import thread
import socket
import re
import sys
import os

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.dominio=''
    tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
    self.type = data[-4:-2]           # Hackish -- this is where the type bits live -- 2 away from the last 4 bytes of the request.

    if tipo == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.dominio+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

# Because python doesn't have native ENUM in 2.7:
TYPE = {
    "\x00\x01":"A",
    "\x00\x1c":"AAAA",
    "\x00\x05":"CNAME",
    "\x00\x0c":"PTR",
    "\x00\x10":"TXT",
    "\x00\x0f":"MX"
}

# Stolen: https://github.com/learningequality/ka-lite/blob/master/python-packages/django/utils/ipv6.py#L209
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

# Stolen: https://github.com/learningequality/ka-lite/blob/master/python-packages/django/utils/ipv6.py#L209
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

    new_ip = []
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
    def __init__(self,query):
        self.id = query.data[:2]        # Use the ID from the request.
        self.flags = "\x81\x80"         # No errors, we never have those.
        self.questions = query.data[4:6]# Number of questions asked...
        self.rranswers = "\x00\x01"     # Answer RRs (Answer resource records contained in response) 1 for now.
        self.rrauthority = "\x00\x00"   # Same but for authority
        self.rradditional = "\x00\x00"  # Same but for additionals.
        self.query = query.data[12:]    # The original query is contained in the response
        self.pointer = "\xc0\x0c"       # The pointer to the resource record - seems to always be this value.
        self.type = None                # This value is set by the subclass and is defined in TYPE dict.
        self.dnsclass = "\x00\x01"      # "IN" class.
        self.ttl = "\x00\x00\x00\x01"   # TODO: Make this adjustable - 1 is good for noobs/testers
        self.length = None              # Set by subclass because is variable except in A/AAAA records.
        self.data = None                # Same as above.

    def make_packet(self):
        try:
            self.packet = self.id + self.flags + self.questions + self.rranswers + self.rrauthority + self.rradditional + self.query + self.pointer + self.type + self.dnsclass + self.ttl + self.length + self.data
        except:
            pdb.set_trace()
        return self.packet


# All classess need to set type, length, and data fields of the DNS Response
# Finished
class A(DNSResponse):
    def __init__(self,query,record):
        super(A,self).__init__(query)
        self.type = "\x00\x01"
        self.length = "\x00\x04"
        self.data = self.get_ip(record,query)

    def get_ip(self,dns_record,query):
        ip = dns_record
        # Convert to hex
        return str.join('',map(lambda x: chr(int(x)), ip.split('.')))

# Not implemented, need to get ipv6 to translate correctly into hex
class AAAA(DNSResponse):
    def __init__(self,query,address):
        super(AAAA,self).__init__(query)
        self.type = "\x00\x1c"
        self.length = "\x00\x10"
        self.data = address # Address is already encoded properly for the response at rule-builder

    # Thanks, stackexchange! http://stackoverflow.com/questions/16276913/reliably-get-ipv6-address-in-python
    def get_ip_6(host, port=0):
        # search only for the wanted v6 addresses
        result = socket.getaddrinfo(host, port, socket.AF_INET6)
        # Will need something that looks like this: 
        ip = result[0][4][0] # just returns the first answer and only the address

# Not yet implemented
class CNAME(DNSResponse):
    def __init__(self,query):
        super(CNAME,self).__init__(query)
        self.type = "\x00\x05"

# Not yet implemented
class PTR(DNSResponse):
    def __init__(self,query,ptr_entry):
        super(PTR,self).__init__(query)
        self.type = "\x00\x0c"

        ptr_split = ptr_entry.split('.')
        ptr_entry = "\x07".join(ptr_split)

        self.data = "\x0e" + ptr_entry + "\x00"
        self.data = "\x132-8-8-8\x02lulz\x07com\x00"
        self.length = chr(len(ptr_entry)+2)
        # Again, must be 2-byte value.
        if self.length < '\xff':
            self.length = "\x00"+self.length

# Finished
class TXT(DNSResponse):
    def __init__(self,query,txt_record):
        super(TXT,self).__init__(query)
        self.type = "\x00\x10"
        self.data = txt_record
        self.length = chr(len(txt_record)+1)
        # Must be two bytes.
        if self.length < '\xff':
            self.length = "\x00"+self.length
        # Then, we have to add the TXT record length field!  We utilize the length field for this since it is already in the right spot
        self.length = self.length+chr(len(txt_record))

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
    def __init__(self,query):
        super(NONEFOUND,self).__init__(query)
        self.type = query.type
        self.flags = "\x81\x83"
        self.rranswers = "\x00\x00"
        self.length = "\x00\x00"
        self.data = "\x00"
        print ">> Built NONEFOUND response"

class ruleEngine:
    def __init__(self,file):
        self.re_list = []
        print '>>', 'Parse rules...'
        with open(file,'r') as rulefile:
            rules = rulefile.readlines()
            for rule in rules:
                splitrule = rule.split()

                # Make sure that the record type is one we currently support
                # TODO: Straight-up let a user define a custome response type byte if we don't have one.
                if splitrule[0] not in TYPE.values():
                    print "Malformed rule : " + rule + " Not Processed."
                    continue

                # We need to do some housekeeping for ipv6 rules and turn them into full addresses if they are shorts.
                # I could do this at match-time, but i like speed, so I've decided to keep this in the rule parser and then work on the logging separate    
                if splitrule[0] == "AAAA":
                    if _is_shorthand_ip(splitrule[2]):
                        splitrule[2] = _explode_shorthand_ip_string(splitrule[2])
                    # OK Now we need to get the ip broken into something that the DNS response can have in it
                    splitrule[2] = splitrule[2].replace(":","").decode('hex')
                    # That is what goes into the DNS request.

                # If the ip is 'self' transform it to local ip.
                if splitrule[2] == 'self':
                    try:
                        ip = socket.gethostbyname(socket.gethostname())
                    except:
                        print ">> Could not get your IP address from your DNS Server."
                        ip = '127.0.0.1'
                    splitrule[2] = ip

                self.re_list.append([splitrule[0],re.compile(splitrule[1]),splitrule[2]])
                
                # TODO: More robust logging system - printing ipv6 rules requires specialness since I encode the ipv6 addr in-rule
                if splitrule[0] == "AAAA":
                    print '>>', splitrule[1], '->', splitrule[2].encode('hex')
                else:
                    print '>>', splitrule[1], '->', splitrule[2]

            print '>>', str(len(rules)) + " rules parsed"

    # Matching has now been moved into the ruleEngine so that we don't repeat ourselves
    def match(self,query):
        for rule in self.re_list:
            # Match on the domain, then on the query type
            if rule[1].match(query.dominio):
                if query.type in TYPE.keys() and rule[0] == TYPE[query.type]:
                    # OK, this is a full match, fire away with the correct response type:
                    response = CASE[query.type](query,rule[2])
                    return response.make_packet()
            
        # OK, we don't have a rule for it, lets see if it exists...
        try:
            # We need to handle the request potentially being a TXT,A,MX,ect... request.
            # So....we make a socket and literally just forward the request raw to our DNS server.
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            addr = ('8.8.8.8',53)
            s.sendto(query.data,addr)
            data,addr = s.recvfrom(1024)
            print "Unmatched Request " + query.dominio
            return data
        except:
            # We really shouldn't end up here, but if we do, we want to handle it gracefully and not let down the client.
            # The cool thing about this is that NOTFOUND will take the type straight out of
            # the query object and build the correct query response type from that automagically
            print ">> Error was handled by sending NONEFOUND"
            return NONEFOUND(query).make_packet()

# Convenience method for threading.
def respond(data,addr):
    p=DNSQuery(data)
    response = rules.match(p)
    #response = Respuesta(p,re_list).packet
    udps.sendto(response, addr)
    return 0

if __name__ == '__main__':
  # Default config file path.
  path = 'dns.conf'

  # Specify a config path.
  if len(sys.argv) == 2:
    path = sys.argv[1]
  if not os.path.isfile(path):
    print '>> Please create a "dns.conf" file or specify a config path: ./fakedns.py [configfile]'
    exit()
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  try:
    rules = ruleEngine(path)
    re_list = rules.re_list
    while 1:
      # I can see this getting messy if we recieve big requests
      data, addr = udps.recvfrom(1024)
      thread.start_new_thread(respond,(data,addr))
  except KeyboardInterrupt:
    print 'Finalizando'
    udps.close()

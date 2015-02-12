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
    "\x00\x10":"TXT"
}

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

class AAAA(DNSResponse):
    def __init__(self,query):
        super(AAAA,self).__init__(query)
        self.type = "\x00\x1c"

    # Thanks, stackexchange! http://stackoverflow.com/questions/16276913/reliably-get-ipv6-address-in-python
    def get_ip_6(host, port=0):
        # search only for the wanted v6 addresses
        result = socket.getaddrinfo(host, port, socket.AF_INET6)
        # Will need something that looks like this: 
        #map(lambda x: chr(int(x)), ip.split('.'))
        return result[0][4][0] # just returns the first answer and only the address

class CNAME(DNSResponse):
    def __init__(self,query):
        super(CNAME,self).__init__(query)
        self.type = "\x00\x05"

class PTR(DNSResponse):
    def __init__(self,query):
        super(PTR,self).__init__(query)

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

                # If the ip is 'self' transform it to local ip.
                if splitrule[2] == 'self':
                    try:
                        ip = socket.gethostbyname(socket.gethostname())
                    except:
                        print ">> Could not get your IP address from your DNS Server."
                        ip = '127.0.0.1'
                    splitrule[2] = ip

                self.re_list.append([splitrule[0],re.compile(splitrule[1]),splitrule[2]])
                print '>>', splitrule[1], '->', splitrule[2]
            print '>>', str(len(rules)) + " rules parsed"

    # Matching has now been moved into the ruleEngine so that we don't repeat ourselves
    def match(self,query):
        for rule in self.re_list:
            # Match on the domain, then on the query type
            if rule[1].match(query.dominio):
                if rule[0] == TYPE[query.type]:
                    # OK, this is a full match, fire away with the correct response type:
                    response = CASE[query.type](query,rule[2])
                    return response.make_packet()
            
        # OK, we don't have a rule for it, lets see if it exists...
        try:
            # We need to handle the request potentially being a TXT,A,MX,ect... request.
            # So....we make a socket and literally just forward the request raw to our DNS server.

            response = CASE[query.type](query,rule[2])
            return response.make_packet()
        except:
            # The cool thing about this is that NOTFOUND will take the type straight out of
            # the query object and build the correct query response type from that automagically
            return NONEFOUND(query).make_packet()

# Convenience method for threading -- helps implement a DNS proxy
def passthru():
    s = socket(AF_INET,SOCK_DGRAM)
    addr = (host,port)
    s.sendto(data,addr)
    data,addr = s.recvfrom(buf)
    
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

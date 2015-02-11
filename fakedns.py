#!/usr/bin/python
"""													"""
"""                    Fakedns.py					"""
"""    A regular-expression based DNS MITM Server	"""
"""						by: Crypt0s					"""
# Adapted from https://github.com/jimmykane/Roque-Dns-Server to follow DNS specs-ish
# Jimmykane's version was in turn modified from an activestate recipe : http://code.activestate.com/recipes/491264-mini-fake-dns-server/
# I then modified it to be more efficient, support a config file, regular expression matching, passthrough requests, and proper "not found" responses
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
    if tipo == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.dominio+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

#because python doesn't have native ENUM in 2.7:
TYPE = {
    "A":"\x00\x01",
    "AAAA":"\x00\x1c",
    "CNAME":"\x00\x05",
    "PTR":"\x00\x0c",
    "TXT":"\x00\x10"
}

class DNSResponse(object):
    def __init__(self,query):
        self.id = query.data[:2]        # Use the ID from the request.
        self.flags = "\x81\x83"         # No errors, we never have those.
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
        self.packet = self.id + self.flags + self.questions + self.rranswers + self.rrauthority + self.rradditional + self.query + self.pointer + self.type + self.dnsclass + self.ttl + self.length + self.data
        return self.packet

class NONEFOUND(DNSResponse(object):
    def __init__(NONEFOUND,self).__init__()
        self.rranswers = "\x00\x00"

class TXT(DNSResponse):
    def __init__(self,txt_record):
        super(TXT,self).__init__()
        self.type = TYPE['TXT']
        self.data = txt_record
        # Need to pad this with an additional \x00 if the len is not enough
        self.length = hex(len(txt_record))


class Respuesta:
    def __init__(self, query,re_list):
        self.data = query.data
        self.packet=''
        ip = None
        for rule in re_list:
            result = rule[1].match(query.dominio)
            if result is not None:
                ip = rule[2]
                print ">> Matched Request: " + query.dominio + ":" + ip

        # We didn't find a match, get the real ip
        if ip is None:
            try:
                ip = socket.gethostbyname(query.dominio)
                print ">> Unmatched request: " + query.dominio + ":" + ip
            except:
                # That domain doesn't appear to exist, build accordingly
                print ">> Unable to parse request"
                # Build the response packet
                self.packet+=self.data[:2] + "\x81\x83"                         # Reply Code: No Such Name
                #							0 answer rrs   0 additional, 0 auth
                self.packet+=self.data[4:6] + '\x00\x00' + '\x00\x00\x00\x00'   # Questions and Answers Counts
                self.packet+=self.data[12:]                                     # Original Domain Name Question

#        # Quick Hack
#        if self.packet == '':
#            # Build the response packet
#            self.data[:2] #transaction ID
#            self.packet+=self.data[:2] + "\x81\x80"                             # NO ERROR flags
#            self.packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
#            self.packet+=self.data[12:]                                         # Original Domain Name Question
#            self.packet+='\xc0\x0c'                                             # Pointer to domain name
#            self.packet+=query.type
#            self.packet+='\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
#            self.packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP

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
                if splitrule[0] not in TYPE.keys():
                    print "Malformed rule : " + rule + " Not Processed."
                    continue

                # If the ip is 'self' transform it to local ip.
                if splitrule[2] == 'self':
                    ip = socket.gethostbyname(socket.gethostname())
                    splitrule[2] = ip

                self.re_list.append([splitrule[0],re.compile(splitrule[1]),splitrule[2]])
                print '>>', splitrule[1], '->', splitrule[2]
            print '>>', str(len(rules)) + " rules parsed"

def respond(data,addr):
  p=DNSQuery(data)
  response = Respuesta(p,re_list).packet
  udps.sendto(response, addr)


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
      data, addr = udps.recvfrom(1024)
      thread.start_new_thread(respond,(data,addr))
  except KeyboardInterrupt:
    print 'Finalizando'
    udps.close()

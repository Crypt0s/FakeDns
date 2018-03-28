# This is a for-fun implementation of DNSQuery.  Hurrah, this is useful!
import socket
import multiprocessing
from multiprocessing import Pool
#from DNSQuery import DNSQuery
from fakedns import DNSQuery

def _resolve(packet):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = s.sendto(packet,('8.8.8.8', 53))
    response = s.recv(1024) # probably not enough for all situations - TODO: improve this
    s.close()
    # I just realized I need to be able to feed a response into something in order to get the data back out...
    return response

def mass_resolve(list):
    queries = []
    for domain_name in list:
        queries.append(DNSQuery(query=domain_name).packet)

    query_sender_pool = Pool(4)
    # Note: This will *not* return until all the map operations have completed _successfully_
    results = query_sender_pool.map(_resolve,queries)

#    for i in results:
#

    return results

print mass_resolve(['google.com','yahoo.com','gmail.com','asdf.com'])

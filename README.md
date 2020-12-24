FakeDns
=======
Update 4/14/2020 - Python 2 support removed and code swapped to Python3

Now with round-robin & improved options!

Bugs:
@crypt0s - Twitter

bryanhalf@gmail.com - Email


A python regular-expression based DNS server!

    USAGE:
    ./fakedns.py [-h] -c Config path [-i interface IP address] [--rebind]

The dns.conf should be set the following way:

    [RECORD TYPE CODE] [python regular expression] [answer] [rebind answer]

The answer could be a ip address or string `self`,
the `self` syntax sugar will be translated to your current machine's local ip address, such as `192.168.1.100`.

If a match is not made, the DNS server will attempt to resolve the request using whatever you have your DNS server set to on your local machine and will proxy the request to that server on behalf of the requesting user.


Supported Request Types
=======================
    - A
    - TXT
    - AAAA
    - PTR
    - SOA

In-Progress Request Types
=========================
    - MX
    - CNAME

Misc
====
    - Supports DNS Rebinding
    - Supports round-robin

Round-Robin
===========
Round-robin rules are implemented.  Every time a client requests a matching rule, FakeDNS will serve out the next IP in the list of IP's provided in the rule.  
A list of IP's is comma-separated.


For example:

    A robin.net 1.2.3.4,1.1.1.1,2.2.2.2

Is a round-robin rule for robin.net which will serve out responses pointing to 1.2.3.4, 1.1.1.1, and 2.2.2.2, iterating through that order every time a request is made by any client for the robin.net entry.

*NOTE* : These IP's aren't included as a list to the client in the response - they still only get just one IP in the response (could change that later)

DNS Rebinding
=============
FakeDNS supports rebinding rules, which basically means that the server accepts a certain number of requests from a client for a domain until a threshold (default 1 request) and then it changes the IP address to a different one.

For example:

    A rebind.net 1.1.1.1 10%4.5.6.7

Means that we have an A record for rebind.net which evaluates to 1.1.1.1 for the first 10 tries.  On the 11th request from a client which has already made 10 requests, FakeDNS starts serving out the second ip, 4.5.6.7

You can use a list of addresses here and FakeDNS will round-robin them for you, just like in the "regular" rule.


Testing FakeDNS in Docker
======
_(localhost only without extra steps)_

I have had a lot of success testing/developing FakeDNS in Docker because it's easier than running it natively on modern Ubuntu installs which have their own DNS services running on port 53 already.

If you want to try it out, you can do so without much heavy lifting by following these steps:

Assuming you are **_inside the FakeDns directory_**: `sudo docker run --interactive --tty --volume \`pwd\`:/opt/FakeDns -p 5353:53/udp python:3.8 /opt/FakeDns/fakedns.py -c /opt/FakeDns/dns.conf.example`. And to test you can run `nslookup -port=5353 testrule.test 127.0.0.1` which should return `1.1.1.1` on your first request

Or, if you'd like to use docker-compose, simply run `docker-compose up` and use the same test as above.
FakeDns
=======

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

In-Progress Request Types
=========================
    - MX
    - PTR
    - CNAME

Misc
====
    - Supports DNS Rebinding


DNS Rebinding
=============

FakeDNS can support a DNS rebinding attack through the --rebind flag.  This flag will log each rule match from each client and will respond with the first address/entry the first time, and the second address/entry on every subsequent request.
    

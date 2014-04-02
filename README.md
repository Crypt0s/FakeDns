FakeDns
=======

Bugs:
@crypt0s - Twitter
bryanhalf@gmail.com - Email


A regular-expression based python MITM DNS server with correct DNS request passthrough and "Not Found" responses.

    USAGE:

    ./fakedns.py [config file]

The default config file name is 'dns.conf'.

The dns.conf should be set the following way:

    [python regular expression] [answer]

The answer could be a ip address or string `self`,
the `self` syntax sugar will be tranlate to your current machine's local ip address,
such as `192.168.1.100`.

The DNS server will take care of the rest, just have a valid regex in the first part.
This server handles only A record requests.  If there's enough interest, I'll implement other requests/responses.

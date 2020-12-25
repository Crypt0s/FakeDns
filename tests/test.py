#!/bin/env python3
# -*- coding: utf-8 -*-
"""Test framework for FakeDns"""


"""Imported Libraries

unittest - Unit Testing Python Framework
socket - Do one cheap DNS Lookup variant 
dns - DNS Query library
"""
import unittest
import socket
import dns.resolver


"""Global Variables

"""


class DNSTestCase(unittest.TestCase):
    """Parent Class to give common function and setUp
    """


    def _dns_lookup(self, q: str, record_type: str) -> str:
        """Does a DNS lookup for us, and returns the string

        :param q: query (ip or hostname)
        :type q: str
        :param record_type: DNS record type
        :type record_type: str
        :return: DNS response
        :rtype: str
        """
        # Ask the DNS server
        answer = self.resolver.resolve(q, record_type)
        # Make sure we only got one response
        if len(answer.rrset) != 1:
            raise RuntimeError(
                "ERROR: More than one record set return in _dns_lookup(\"{}\", \"{}\")".format(q, record_type)
            )
        # Return the value
        return answer.rrset[0].to_text()


    def setUp(self):
        """Creates the FakeDns Process
        """
        # Determine FakeDns IP address to use that as the name server
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [socket.gethostbyname('FakeDns')] # Can't lookup 'FakeDns' via dns.resolver


class TestRecordTypes(DNSTestCase):
    """Checks the return of specific DNS Requests to ensure all record types are working as intended
    """


    def tearDown(self):
        """Destroys the FakeDns process
        """
        del self.resolver    


    def test_ARecord(self):
        """Tests A Record
        """
        dns_response = self._dns_lookup("test.reddit.com", "A")
        self.assertEqual(dns_response, "8.8.8.8")


    def test_TXTRecord(self):
        """Tests TXT Record
        """
        dns_response = self._dns_lookup("anyvalue", "TXT")
        self.assertEqual(dns_response, "\"HELLO\"")


    def test_AAAARecord(self):
        """Tests AAAA Record
        """
        dns_response = self._dns_lookup("lulz.com", "AAAA")
        self.assertEqual(dns_response, "2607:f8b0:4006:807::100e")


    def test_PTRRecord(self):
        """Tests PTR Record
        """
        dns_response = self._dns_lookup("1.0.0.127", "PTR")
        self.assertEqual(dns_response, "localhost.")


    def test_SOARecord(self):
        """Tests SOA Record
        """
        dns_response = self._dns_lookup("example.com", "SOA")
        self.assertEqual(dns_response, "ns.icann.org. noc.dns.icann.org. 2020121101 7200 3600 1209600 3600")


class TestFeatures(DNSTestCase):
    """Tests various DNS features implemented in FakeDns
    """


    def test_Rebinding(self):
        """Test DNS rebinding
        """
        # We do two rounds because we want to make sure the "wrapping around" feature doesn't break
        answers = [self._dns_lookup("testrule.test", "A") for _ in range(6)]
        expected_answers = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "1.1.1.1", "2.2.2.2", "3.3.3.3"]
        self.assertEqual(answers, expected_answers)


    def test_RoundRobin(self):
        """Test DNS roundrobin
        """
        # We do two rounds because we want to make sure the "wrapping around" feature doesn't break
        answers = [self._dns_lookup("roundrobin", "A") for _ in range(13)]
        expected_answers = ["1.1.1.1"] * 10 + ["2.2.2.2", "3.3.3.3", "4.4.4.4"]
        self.assertEqual(answers, expected_answers)


if __name__ == "__main__":
    unittest.main()

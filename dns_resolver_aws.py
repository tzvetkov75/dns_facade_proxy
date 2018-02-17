#!/usr/bin/python
#
#   simple resolver for aws hosts that set aa flag
#
#
#
import dnslib


d = dnslib.DNSRecord.question("google.com")

print(d)




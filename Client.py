import random

__author__ = 'tomirio619 & jusser'

import socket
import struct


def packsubstring(substr):
    out = ""
    for c in substr:
        out += struct.pack('!B', ord(c))
    return out


def encode(address):
    #maak DNS query, genereer 16 bit ID (mag niet gebruikt zijn)
    ID = random.getrandbits(16)
    FlgsNCodes = 256  # RD = 1
    out = struct.pack('!6H', ID, FlgsNCodes, 1, 0, 0, 0)

    splittedAddress = address.split(".")
    buf = bytearray(b'')
    for str in splittedAddress:
        length = len(str)
        out += struct.pack('!B', length)
        out += packsubstring(str)
    out += struct.pack('!B2h', 0, 1, 1)
    return out


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print 'Starting client'
    address = 'localhost'
    port = 53
    server_address = (address, port)

    # Question bestaat uit query type (QTYPE), query class (QCLASS) en query domain name (QNAME)
    # Zie rfc1035 4.1.2 voor question section format

    # http://www.zytrax.com/books/dns/ch15/
    # We houden alleen rekening met Resource Records van type A en CNAME van klasse IN
    # We moeten werken met een byte-array

    DNSmsg = encode("www.spele.nl")
    sock.sendto(DNSmsg, server_address)


if __name__ == "__main__":
    main()
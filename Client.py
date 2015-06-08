import utils

__author__ = 'tomirio619 & jusser'

from threading import Thread
import socket
import struct


def packsubstring(substr):
    out = ""
    for c in substr:
        out += struct.pack('!B', ord(c))
    return out


def sendQuery(msg, address='localhost', port=53):
    query = utils.encode(msg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, port)
    sock.sendto(query, server_address)


def main():
    print 'Starting client'

    # Question bestaat uit query type (QTYPE), query class (QCLASS) en query domain name (QNAME)
    # Zie rfc1035 4.1.2 voor question section format

    # http://www.zytrax.com/books/dns/ch15/
    # We houden alleen rekening met Resource Records van type A en CNAME van klasse IN
    # We moeten werken met een byte-array
    DNSmsgs = [
    "www.mijn-daltons.nl",
    "www.hotmail.com",
    "www.pornhub.com",
    "www.yahoo.com",
    # "mail.fishcom.ru"
    ]
    for msg in DNSmsgs:
        t = Thread(target = sendQuery, args = (msg, 'localhost', 53))
        t.start()

if __name__ == "__main__":
    main()
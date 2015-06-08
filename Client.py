__author__ = 'Tom Sandmann (s4330048) & Justin Mol (s4386094)'

from threading import Thread
import utils
import socket
import struct
import select


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

    whatReady = select.select([sock], [], [])
    if whatReady:
        response = sock.recv(512*8)
        header, Qs, ANs, NSs, ARs = utils.dissectDNS(response)
        print "Server: localhost"
        print "Adress: localhost#53"
        print "Authoritative answer:" if utils.isAA(response) else "Non-authoritative answer"
        for AR in ARs:
            ARname = AR[0]
            IP = AR[5]
            print "Name: " + ARname
            print "Address: " + IP


def main():
    print 'Starting client'
    DNSmsgs = [
    "www.mijn-daltons.nl"
    # "mail.fishcom.ru"
    ]
    for msg in DNSmsgs:
        t = Thread(target = sendQuery, args = (msg, 'localhost', 53))
        t.start()

if __name__ == "__main__":
    main()
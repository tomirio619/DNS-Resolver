__author__ = 'tomirio619'

import socket
import struct
import select

def resolve(query, dnsIP):
    print 'We gaan een query ontleden'
    print 'De query is als volgt: ' + query + '\n'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (dnsIP, 53))
    whatReady = select.select([sock], [], [])
    if whatReady != []:
        rcvd = sock.recv(512*8)
        print rcvd




def printInfo(pkt):
    length = len(pkt)
    print '---------------------'
    print 'IP PACKET\n---------------------'
    print 'Length: ', length
    ipHeader = pkt[0:20]
    (src1,src2,src3,src4, dst1,dst2,dst3,dst4) = struct.unpack('!12x8B', ipHeader)
    print 'Source address: {}.{}.{}.{}'.format(src1,src2,src3,src4)
    print 'Dest address: {}.{}.{}.{}'.format(dst1,dst2,dst3,dst4)
    print '---------------------'
    print 'UDP PACKET\n---------------------'
    udpHeader = pkt[20:28]
    srcprt, destprt, length = struct.unpack('!3H2x', udpHeader)
    print 'length: ', length
    print 'Source port: ', srcprt
    print 'Dest port: ', destprt
    udpData = pkt[28:length-len(udpHeader)]
    print 'UDP data: ' + udpData

def dissect(pkt):
    ipHeader = pkt[0:20]
    udpHeader = pkt[20:28]
    srcprt, destprt, length = struct.unpack('!3H2x', udpHeader)
    udpData = pkt[28:28+length]
    return ipHeader, udpHeader, udpData


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    print 'Starting resolver'
    address = 'localhost'
    port = 53
    server_address = (address, port)
    sock.bind(server_address)

    while True:
        #We pakken eerst de eerste 160 bits (20 bytes) UDP Header en DNS Header bevat
        whatReady = select.select([sock], [], [])
        if whatReady != []:
            pkt = sock.recv(20*80)
            printInfo(pkt)
            ipHeader, udpHeader, udpData = dissect(pkt)

            if len(udpData) >= 12:
                try:
                    resolve(udpData, '198.41.0.4') #131.174.117.20')
                except struct.error:
                    print 'Not a dns query'


if __name__ == "__main__":
    main()
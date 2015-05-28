__author__ = 'tomirio619'

import socket
import struct
import select


def makeNonRecursive(query):
    qheader = query[0:12]
    ID, Flgs1, Flgs2, Qcount, Answercount, NScount, Additionalcount = struct.unpack('!H2B4H', qheader)
    newFlgs1 = int(Flgs1) & 254
    qheader = struct.pack('!H2B4H', ID, newFlgs1, Flgs2, Qcount, Answercount, NScount, Additionalcount)
    return qheader + query[12:]


def skipName(data):
    nextlen = ord(data[0])          #waarde van data is op een gegeven moment leeg, vandaar de error
    print 'de waarde van nextlen is ', nextlen
    print 'de data is als volgt:', data
    if nextlen > 0:
        return skipName(data[nextlen + 1:])
    else:
        data = data[1:]
        print 'Naam is eraf gesnoepd, we returnen de data:', data
        return data


def stripRR(data):
    data = skipName(data)
    print 'levert dit al een error op?'
    #print data
    data = data[8:]  # Snoep TYPE, CLASS, TTL van data af
    RDLENGTH = struct.unpack_from('!H', data)[0]
    #print "Waarde van RDLENGHT is ", RDLENGTH
    data = data[2+RDLENGTH:]  # Snoep RDLENGTH + RDATA van data af
    return data


def getNextIP(response):
    header = response[0:12]
    data = response[12:]
    print 'de lengte van data voor bewerken is ', len(data)
    ANCount, NSCount, ARCount = struct.unpack("!6x3H", header)
    while NSCount > 0:
        data = stripRR(data)
        print 'We hebben waarde NSCount van ', NSCount
        print 'De stripped data heeft een lengte van ', len(data)
        NSCount -= 1

    print 'Uiteindelijke lengte van data is ', len(data)

    return 'HAII'


def resolve(query, dnsIP):
    # print 'We gaan een query ontleden'
    # print 'De query is als volgt: ' + query

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (dnsIP, 53))
    whatReady = select.select([sock], [], [])
    if whatReady != []:
        rcvd = sock.recv(512*8)
        # print rcvd

        sock.close()
        nextIP = getNextIP(rcvd)
        # resolve(query, nextIP)


def printInfo(pkt):
    length = len(pkt)
    print '---------------------'
    print 'IP PACKET\n---------------------'
    print 'Length: ', length
    ipHeader = pkt[0:20]
    (src1, src2, src3, src4, dst1, dst2, dst3, dst4) = struct.unpack('!12x8B', ipHeader)
    print 'Source address: {}.{}.{}.{}'.format(src1, src2, src3, src4)
    print 'Dest address: {}.{}.{}.{}'.format(dst1, dst2, dst3, dst4)
    print '---------------------'
    print 'UDP PACKET\n---------------------'
    udpHeader = pkt[20:28]
    srcprt, destprt, length = struct.unpack('!3H2x', udpHeader)
    print 'length: ', length
    print 'Source port: ', srcprt
    print 'Dest port: ', destprt
    udpData = pkt[28:28+length]
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
            #printInfo(pkt)
            ipHeader, udpHeader, udpData = dissect(pkt)

            if len(udpData) >= 12:
                #try:
                resolve(udpData, '198.41.0.4') #131.174.117.20')
                #except struct.error:
                 #   print 'Not a DNS-query'


if __name__ == "__main__":
    main()
__author__ = 'tomirio619'

import random
import struct

ATYPE = 1
NSTYPE = 2
CNAMETYPE = 5


def packsubstring(substr):
    out = ""
    for c in substr:
        out += struct.pack('!B', ord(c))
    return out


def encode(address, recursionDesired=True, ID=''):
    #maak DNS query, genereer 16 bit ID (mag niet gebruikt zijn)
    if ID == '':
        ID = random.getrandbits(16)
    FlagsNCodes = recursionDesired if 1 << 8 else 0
    out = struct.pack('!6H', ID, FlagsNCodes, 1, 0, 0, 0)

    splittedAddress = address.split(".")
    for str in splittedAddress:
        length = len(str)
        out += struct.pack('!B', length)
        out += packsubstring(str)
    out += struct.pack('!B2H', 0, 1, 1)
    return out


def printInfo(pkt):
    length = len(pkt)
    print '---------------------'
    print 'IP PACKET\n---------------------'
    print 'Length: ', length
    ipHeader = pkt[0:20]
    src1, src2, src3, src4, dst1, dst2, dst3, dst4 = struct.unpack('!12x8B', ipHeader)
    print 'Source address: {}.{}.{}.{}'.format(src1,src2,src3,src4)
    print 'Dest address: {}.{}.{}.{}'.format(dst1,dst2,dst3,dst4)
    print '---------------------'
    print 'UDP PACKET\n---------------------'
    udpHeader = pkt[20:28]
    srcprt, destprt, length = struct.unpack('!3H2x', udpHeader)
    print 'length: ', length
    print 'Source port: ', srcprt
    print 'Dest port: ', destprt
    udpData = pkt[28:28+length]
    print 'UDP data: ' + udpData


# Dissects an IP packet
def dissectIP(pkt):
    ipHeader = pkt[0:20]
    udpHeader = pkt[20:28]
    srcprt, destprt, length = struct.unpack('!3H2x', udpHeader)
    udpData = pkt[28:28+length]
    return ipHeader, udpHeader, udpData


# Dissects DNS packet
def dissectDNS(pkt):
    header = pkt[0:12]
    data = pkt[12:]
    QCount, ANCount, NSCount, ARCount = struct.unpack("!4x4H", header)
    # print 'Questions:', QCount, 'Answers:', ANCount, 'Name Servers:', NSCount, 'Additional Records:', ARCount
    Qs = []
    ANs = []
    NSs = []
    ARs = []

    # Read out all DNS sections from response
    while QCount > 0:
        Q, data = readQuestion(data)
        Qs.append(Q)
        # print Q
        QCount -= 1

    while ANCount > 0:
        AN, data = readRR(data, pkt)
        ANs.append(AN)
        # print AN
        ANCount -= 1

    while NSCount > 0:
        NS, data = readRR(data, pkt)
        NSs.append(NS)
        # print NS
        NSCount -= 1

    while ARCount > 0:
        AR, data = readRR(data, pkt)
        if AR is not None:
            ARs.append(AR)
            # print AR
        ARCount -= 1

    return header, Qs, ANs, NSs, ARs


def readRR(data, original):
    name, data = readName(data, '', original)
    if name == '':
        name = '<Root>'
    TYPE, CLASS, TTL, RDLENGTH = struct.unpack_from('!2HIH', data)
    data = data[10:]  # Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH(2)
    RDATA = data[0:RDLENGTH]

    if TYPE == ATYPE:  # Data is an IP address
        RDATA = readIP(RDATA)
    elif TYPE == NSTYPE:  # Data is a name
        RDATA, _ = readName(RDATA, '', original)
    elif TYPE == CNAMETYPE:  # Data is also a name
        RDATA, _ = readName(RDATA, '', original)
    else:
        # log('readRR', 'Unsupported type: ' + str(TYPE))
        return None, data[RDLENGTH:]

    data = data[RDLENGTH:]  # Skip RDATA (RDLENGTH)
    return (name, TYPE, CLASS, TTL, RDLENGTH, RDATA), data


def readQuestion(data):
    name, data = readName(data)
    QTYPE = data[0:2]
    QCLASS = data[2:4]
    data = data[4:]  # Skip QTYPE (2), QCLASS (2)
    question = (name, QTYPE, QCLASS)
    return question, data


def readName(data, name='', original=''):
    # log('readName', repr(data[0:10]) + ' ... ' + name)

    if len(data) >= 2:
        first2bytes = struct.unpack_from('!H', data)[0]
        first2bits = (first2bytes >> 14) & 3  # The two most significant bits indicate a pointer

        if first2bits == int('11', 2):  # It starts with 11, so we've got a pointer!
            ptr = first2bytes & int('0011111111111111', 2)  # The rest of the bits are the pointer itself
            # log('Pointer recursion', ptr, '---')
            name, _ = readName(original[ptr:], name, original)
            return name, data[2:]

    nextlen = ord(data[0])
    if nextlen > 0:
        if name != '':
            name += '.'
        name += data[1:nextlen+1]
        return readName(data[nextlen + 1:], name, original)
    else:
        data = data[1:]
        return name, data


def readIP(RDATA):
    a, b, c, d = struct.unpack_from('!4B', RDATA)
    IPadres = '{}.{}.{}.{}'.format(a, b, c, d)
    return IPadres
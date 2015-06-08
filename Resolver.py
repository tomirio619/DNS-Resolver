__author__ = 'tomirio619'

from threading import Thread, Lock

import socket
import struct
import select
import utils
import time
import datetime

cache = dict()
# TTL of -1 means: never expires
cache['a.root-servers.net'] = (['198.41.0.4'], -1, '')
cache['b.root-servers.net'] = (['192.228.79.201'], -1, '')
cache['c.root-servers.net'] = (['192.33.4.12'], -1, '')
cache['d.root-servers.net'] = (['199.7.91.13'], -1, '')
cache['e.root-servers.net'] = (['192.203.230.10'], -1, '')
cache['f.root-servers.net'] = (['192.5.5.241'], -1, '')
cache['g.root-servers.net'] = (['192.112.36.4'], -1, '')
cache['h.root-servers.net'] = (['128.63.2.53'], -1, '')
cache['i.root-servers.net'] = (['192.36.148.17'], -1, '')
cache['j.root-servers.net'] = (['192.58.128.30'], -1, '')
cache['k.root-servers.net'] = (['193.0.14.129'], -1, '')
cache['l.root-servers.net'] = (['199.7.83.42'], -1, '')
cache['m.root-servers.net'] = (['202.12.27.33'], -1, '')

debuglevel = 1
lock = Lock()


def log(TAG, tolog, tokens=''):
    if debuglevel == 1:
        if tokens != '':
            print tokens+' '+TAG+':', str(tolog) + ' ' + tokens
        else:
            print TAG+':', str(tolog)


def makeNonRecursive(query):
    qheader = query[0:12]
    ID, Flgs1, Flgs2, Qcount, Answercount, NScount, Additionalcount = struct.unpack('!H2B4H', qheader)
    newFlgs1 = int(Flgs1) & 254
    qheader = struct.pack('!H2B4H', ID, newFlgs1, Flgs2, Qcount, Answercount, NScount, Additionalcount)
    return qheader + query[12:]


# Onderstaande functie print de naam van een Resource Record (met extra punt op het einde)
# def printName(data, result):
#     nextlen = ord(data[0])
#     data = data[1:]
#     # print 'de waarde van nextlen is ', nextlen
#     if nextlen > 0:
#         for i in range(0, nextlen):
#             # print 'de waarde van data[i] is ', ord(data[i])
#             result += chr(ord(data[i]))
#         result += "."
#         # print 'het tussenliggende resultaat is:', result
#         return printName(data[nextlen:], result)
#     else:
#         return result


# Return codes for doOneStep:
ANSWER = 0
NOCHANGE = 1
CNAMEQUERY = 2


# Cache is datastructue: ([IP], TTL, cname)
def readCacheFrom(filename):

    return


def writeCacheTo(cache, filename='cache'):
    target = open(filename, 'w')

    for key in cache.keys():
        cachevalue = cache[key]
        IPs = cachevalue[0]

        target.write(key + '\t')

        length = len(IPs)
        for i in range(0, length):
            if i == length-1:
                target.write(IPs[i])
            else:
                target.write(IPs[i] + ', ')
        target.write('\n')


def doOneStep(response):
    # Note: Resource records are saved as (Name, type, class, ttl, rdlength, rdata)
    header, Qs, ANs, NSs, ARs = utils.dissectDNS(response)

    # If we have an answer, return all answers if ATYPE or give next IP and address if only CNAMETYPE present
    if ANs:
        ATypes = listType(ANs, utils.ATYPE)
        CNAMETypes = listType(ANs, utils.CNAMETYPE)
        if ATypes:
            name = Qs[0][0]
            IPs = []
            for AType in ATypes:
                IPs.append(AType[5])
            if CNAMETypes:
                CNAME = CNAMETypes[0][5]
            else:
                CNAME = ''
            cache[name] = (IPs, ATypes[0][3], CNAME)
            print cache[name]
            return ANs, ANSWER
        elif CNAMETypes:
            for CNAME in CNAMETypes:
                address = CNAME[5]
                for NS in NSs:
                    IP = findIP(NS, ARs)
                    if IP is not None:
                        return IP, CNAMEQUERY, address
                print 'Couldn\'t find next IP:', NSs, ',', ARs
                return None, CNAMEQUERY, address
        else:
            print 'Unsupported answer format:', ANs

    if ARs:
        for NS in NSs:
            IP = findIP(NS, ARs)
            if IP is not None:
                return IP, NOCHANGE
    else:
        for NS in NSs:
            NSQuery = utils.encode(NS[5], False)
            IPs = checkCache(NS[5])
            if IPs is None:
                answers = resolve(NSQuery)
                IP = answers[0][5]
            else:
                IP = IPs[0]
            return IP, NOCHANGE


# Cache is datastructue: ([IP], TTL, cname)
def checkCache(name):
    if name in cache:
        cachevalue = cache[name]
        ts = time.time()
        if cachevalue[1] == -1 or ts < cachevalue[1]:
            return cachevalue[0]
        else:  # This cachevalue is expired
            cache.pop(name, None)
            return None
    else:
        return None


# Function that finds IP of a Nameserver Record in the additional records (or in cache)
def findIP(NS, ARs):
    name = NS[0]
    nameserver = NS[5]
    IPs = checkCache(name)
    if IPs is not None:
        return IPs[0]
    else:
        # Find IP of nameserver and save IP in cache
        for AR in ARs:
            ARname = AR[0]
            if nameserver == ARname:
                IP = AR[5]
                TTL = AR[3]  # TTL is in seconds
                expiry = time.time() + TTL

                with lock:
                    cache[name] = ([IP], expiry, '')
                # print 'New cache entry:', name + ':' + str(cache[name])
                return IP


def listType(RRs, type):
    out = list()
    for RR in RRs:
        if RR[1] == type:
            out.append(RR)
    return out


def resolve(query, dnsIP='192.55.83.30'):   # Default IP is local host

    # TODO: Before asking, check cache
    _, Qs, _, _, _ = utils.dissectDNS(query)
    name = Qs[0][0]
    if name in cache:
        return cache[name]

    ID = struct.unpack('!H', query[0:2])[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (dnsIP, 53))

    whatReady = select.select([sock], [], [])
    if whatReady:  # Pythonic way of saying list is not empty
        rcvd = sock.recv(512*8)
        print utils.isAA(rcvd)
        sock.close()
        oneStep = doOneStep(rcvd)
        if oneStep is not None:
            if len(oneStep) == 2:
                if oneStep[1] == NOCHANGE:  # Continue our journey
                    return resolve(query, oneStep[0])
                elif oneStep[1] == ANSWER:
                    _, Qs, _, _, _ = utils.dissectDNS(query)
                    return oneStep[0]
            else:
                # CNAMEQUERY: make query with new address
                address = oneStep[2]
                query = utils.encode(address, False, ID)
                if oneStep[0] is not None:
                    return resolve(query, oneStep[0])
                else:
                    return resolve(query)


def solve(query, dnsIP='192.55.83.30'):
    answer = resolve(query, dnsIP)
    if answer is not None:
        log('Answer for', query, '--')
        print answer
        # log('Cachedump', cache, '-')
        writeCacheTo(cache)


def main():
    # TODO: Read cache from file
    writeCacheTo(cache)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    print 'Starting resolver'
    address = 'localhost'
    port = 53
    server_address = (address, port)
    sock.bind(server_address)

    while True:
        # We pakken eerst de eerste 160 bits (20 bytes) UDP Header en DNS Header bevat
        whatReady = select.select([sock], [], [])
        if whatReady != []:
            pkt = sock.recv(20*80)
            # utils.printInfo(pkt)
            print utils.isAA(pkt)
            ipHeader, udpHeader, udpData = utils.dissectIP(pkt)

            if len(udpData) >= 12:
                query = makeNonRecursive(udpData)
                t = Thread(target = solve, args =(query, '131.174.117.20'))
                t.start()
                # Answer = resolve(udpData, '192.33.4.12')  # root server
                # Answer = resolve(udpData, 131.174.117.20')


if __name__ == "__main__":
    main()
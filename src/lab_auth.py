#!/usr/bin/python3
from datetime import datetime, date
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1902 import Integer, IpAddress, OctetString

import hashlib
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def chkmarapara(devIP, uName, passWord):
    usergroupstatus = chkUserGroup(uName)
    cpustatus = chkDeviceCPU(devIP, "networktocode", uName)
    userpass = chkUserPass(uName, passWord)
    # print(usergroupstatus)
    # print(cpustatus)
    # print(userpass)
    if usergroupstatus == "OK" and cpustatus == "OK" and userpass == "OK":
        return "OK:Arista-AVPair = 'shell:roles=network-admin', Service-Type = NAS-Prompt-User"
    else:
        return "ERR"

def getUserGroup(uName):
    f = open(os.path.join(BASE_DIR,'dbs/ugroup'), 'r')
    # f = open (os.path.join()"/dbs/ugroup", "r")
    for i in f:
        sp = i.split(":")
        if uName == sp[0]:
            whatsUpGroup = sp[1].rstrip('\r\n')
    return whatsUpGroup

def getDeviceCPU(devIP, community):
    cpuUsage = 100
    oid = "1.3.6.1.2.1.25.3.3.1.2"
    community = community
    version = 1
    generator = cmdgen.CommandGenerator()
    comm_data = cmdgen.CommunityData('server', community, version)
    transport = cmdgen.UdpTransportTarget((devIP, 161))
    rf = getattr(generator, 'nextCmd')
    res = (errorIndication, errorStatus, errorIndex, varBinds) = rf(comm_data, transport, oid)
    if not errorIndication is None  or errorStatus is True:
        print("Error: %s %s %s %s" % res)
        return 100
    else:
        # print("%s" % type(varBinds))
        for i in varBinds:
            cpuUsage = i[0][1]
        return int(cpuUsage)

def chkDeviceCPU(devIP, community, uName):
    cpuUsage = getDeviceCPU(devIP, community)
    userGroup = getUserGroup(uName)
    isallowed = "NONE"
    checkpoint = 0
    f = open(os.path.join(BASE_DIR,'dbs/conf'), 'r')
    for i in f:
        sp = i.split(":")
        if "gt" in sp[1]:
            if checkpoint == 0:
                if cpuUsage > int(sp[1].replace("gt", "")):
                    if userGroup in sp[3]:
                        isallowed = "YES"
                        checkpoint = 1
                    else:
                        isallowed = "NO"
                else:
                    isallowed = "NO"
        elif "lt" in sp[1]:
            if checkpoint == 0:
                # print("I am here..")
                if cpuUsage < int(sp[1].replace("lt", "")):
                    if userGroup in sp[3]:
                        isallowed = "YES"
                        checkpoint = 1
                    else:
                        isallowed = "NO"
                else:
                    isallowed = "NO"
    if isallowed == "YES":
        return "OK"
    else:
        return "ERR"

def chkUserPass(uName, passWord):
    f = open(os.path.join(BASE_DIR,'dbs/ugroup'), 'r')
    for i in f:
        sp = i.split(":")
        if uName == sp[0]:
            # print(passWord)
            # print(hashlib.md5(passWord.encode('utf-8')).hexdigest())
            # print(sp[2].rstrip('\r\n'))
            if hashlib.md5(passWord.encode('utf-8')).hexdigest() == sp[2].rstrip('\r\n'):
                return "OK"
            else:
                return "ERR"
        else:
            return "ERR"

def chkUserGroup(uName):
    whatsUpGroup = "nomatch"
    whatsUpGroup = getUserGroup(uName)
    if whatsUpGroup == 'admin':
        status = 'OK'
    elif whatsUpGroup == 'ronly':
        status = 'ERR'
    elif whatsUpGroup == 'rwonly':
        status = 'ERR'
    else :
        status = 'INVALID QUERY'
    return status



if __name__=="__main__":
    # print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    print(chkmarapara(sys.argv[1], sys.argv[2], str(sys.argv[3])))

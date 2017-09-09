from datetime import datetime, date
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1902 import Integer, IpAddress, OctetString

import hashlib
import paramiko
import sys


def chkmarapara(devIP, uName, passWord):
    usergroupstatus = chkUserGroup(uName)
    cpustatus = chkDeviceCPU(devIP, "networktocode", 20)
    userpass = chkUserPass(uName, passWord)
    print(userpass)
    if usergroupstatus == "OK" and cpustatus == "OK" and userpass == "OK":
        return "OK:Arista-AVPair = 'shell:roles=network-admin', Service-Type = NAS-Prompt-User"
    else:
        return "ERR"

def chkUserPass(uName, passWord):
    f = open('../dbs/ugroup', 'r')
    for i in f:
        sp = i.split(":")
        if uName == sp[0]:
            print(passWord)
            print(hashlib.md5(passWord.encode('utf-8')).hexdigest())
            print(sp[2].rstrip('\r\n'))
            if hashlib.md5(passWord.encode('utf-8')).hexdigest() == sp[2].rstrip('\r\n'):
                return "OK"
            else:
                return "ERR"
        else:
            return "ERR"

def chkUserGroup(uName):
    whatsUpGroup = "nomatch"
    f = open ("../dbs/ugroup", "r")
    for i in f:
        sp = i.split(":")
        if uName == sp[0]:
            whatsUpGroup = sp[1].rstrip('\r\n')
            break
    if whatsUpGroup == 'admin':
        status = 'OK'
    elif whatsUpGroup == 'ronly':
        status = 'ERR'
    elif whatsUpGroup == 'rwonly':
        status = 'ERR'
    else :
        status = 'INVALID QUERY'
    return status

def chkDeviceCPU(devIP, community, threShold):
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
    else:
        # print("%s" % type(varBinds))
        for i in varBinds:
            for j in i:
                cpuUsage = str(j).split(" ")[2]
                break
    if int(cpuUsage) <= threShold:
        return "OK"
    else:
        return "ERR "

if __name__=="__main__":
    # print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    print(chkmarapara(sys.argv[1], sys.argv[2], str(sys.argv[3])))

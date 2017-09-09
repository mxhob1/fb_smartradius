from datetime import datetime, date
import paramiko
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1902 import Integer, IpAddress, OctetString


def chkmarapara(devIP, uName, passWord, community, threshold):
    usergroupstatus = chkUserGroup(uName)
    cpustatus = chkDeviceCPU(devIP, community, threshold)

    if usergroupstatus == "OK" and cpustatus == "OK":
        return "OK:Arista-AVPair = 'shell:roles=network-admin', Service-Type = NAS-Prompt-User"
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

import shlex
import sys

enum_address_type = {"iprange","subnet","fqdn"}
enum_protocol = {"tcp","udp","icmp"}
enum_action = {"accept","deny"}
configFileName = "testbed.conf"
outputFileName = "output.conf"
finalFileName = "final.conf"
definitiveFileName = "definitive.conf"
vipTranslationSuffix = "_VIP-TRANSLATION"
vipGrpTranslationSuffix = "_VIPGRP-TRANSLATION"

class ADDRGRP:

    def __init__(self, name):
        self.name = name
        self.member = []

class ADDRESS:

    def __init__(self, name):
        self.name = name
        self.tipo_address = enum_address_type
        self.associatedInterface = ""
        self.startIp = ""
        self.endIp = ""
        self.subnet = ""
        self.fqdn = ""

class FIREWALL_POLICY:

    def __init__(self,edit):
        self.edit = edit
        self.name = ""
        self.srcintf = []
        self.dstintf =[]
        self.srcaddr = []
        self.dstaddr = []
        self.action = enum_action
        self.schedule = ""
        self.service = []
        self.ippool = bool
        self.poolname = ""
        self.natEnable = bool

class VIP:

    def __init__(self,nombre):
        self.name = nombre
        self.extIp = ""
        self.extIntf = ""
        self.portForward = bool
        self.mappedIp = ""
        self.protocol = enum_protocol
        self.extport = 0
        self.mappedport = 0

class VIPGRP:

    def __init__(self,nombre):
        self.name = nombre
        self.intf = ""
        self.member = [] #list of VIP

class VDOM:

    def __init__(self,nombre):
        self.name = nombre
        self.address = [] #list of ADDRESS
        self.addrgrp = [] # list of ADDRGRP
        self.policy = [] #list of FIREWALL_POLICY
        self.vipgrp = [] #list of VIPGRP
        self.vip = [] #list of VIP

class FGT:

    def __init__(self):
        self.vdom = VDOM("LCH")
        level = ""
        configFile = open(configFileName,'r')
        outputFile = open(outputFileName,'w')
        modConfigLine = ""
        newAddresses = []
        newAddrGrp = []
        for configline in configFile:
            escribe = True
            if (configline.count("\"") % 2 != 0):
                writeFile(outputFile, configline)
                continue
            linetokens = shlex.split(configline)
            if len(linetokens) > 1:
                if(linetokens[0] == 'config' and linetokens[1] == 'system' and linetokens[2] == 'settings'):
                    writeFile(outputFile, configline)
                    writeFile (outputFile,"   set central-nat enable\n")
                    escribe = False
                elif ((linetokens[0] == "config" and linetokens[1]=="firewall" and linetokens[2]=="address") or level == "address"):
                    level = "address"
                    if (linetokens[0]=='edit'):
                        auxAddress = ADDRESS(linetokens[1])
                    # elif (linetokens[0]=='set'): SOLO ME INTERESA EL NOMBRE
                        # if (linetokens[1]=='extip'):
                if ((linetokens[0] == "config" and linetokens[1]=="firewall" and linetokens[2]=="addrgrp") or level == "addrgrp"):
                    level = "addrgrp"
                    if (linetokens[0]=='edit'):
                        auxAddrGrp = ADDRGRP(linetokens[1])
                    elif (linetokens[0]=='set' and linetokens[1]=="members"):
                        auxAddrGrp.member = linetokens[2]
                elif ((linetokens[0]=='config' and linetokens[1]=='firewall' and linetokens[2]=='vipgrp') or level == "vipgrp"):
                    # Accessing VIPGRP
                    level = "vipgrp"
                    if (linetokens[0]=='config'):
                        writeFile(outputFile, configline)
                        continue
                    elif (linetokens[0]=='edit'):
                        # VIPGRP name
                        auxVipgrp = VIPGRP(linetokens[1])
                    elif (linetokens[0]=='set'):
                        if (linetokens[1]=='intf'):
                            # VIPGRP intf
                            auxVipgrp.intf = linetokens[2]
                        elif (linetokens[1]=='member'):
                            # VIPGRP member
                            for i in range (2,len(linetokens)):
                                auxVipgrp.member.append(linetokens[i])
                elif ((linetokens[0]=='config' and linetokens[1]=='firewall' and linetokens[2]=='vip') or level == "vip"):
                    # Accessing VIP
                    level = "vip"
                    if (linetokens[0]=='config'):
                        writeFile(outputFile, configline)
                        continue
                    elif (linetokens[0]=='edit'):
                        # VIP name
                        auxVip = VIP(linetokens[1])
                    elif (linetokens[0]=='set'):
                        if (linetokens[1]=='extip'):
                            # VIP extIP
                            auxVip.extIp = linetokens[2]
                        elif (linetokens[1]=='extintf'):
                            # VIP extIntf
                            auxVip.extIntf = linetokens[2]
                        elif (linetokens[1]=='portforward'):
                            # VIP portForward
                            auxVip.portForward = linetokens[2]
                        elif (linetokens[1]=='mappedip'):
                            # VIP mappedIp
                            auxVip.mappedIp = linetokens[2]
                        elif (linetokens[1]=='protocol'):
                            # VIP protocol
                            auxVip.protocol = linetokens[2]
                        elif (linetokens[1]=='extport'):
                            # VIP extport
                            auxVip.extport = linetokens[2]
                        elif (linetokens[1]=='mappedport'):
                            # VIP mappedport
                            auxVip.mappedport = linetokens[2]
                elif ((linetokens[0]=='config' and linetokens[1]=='firewall' and linetokens[2]=='policy') or level == "policy"):
                    # Accessing FIREWALL_POLICY
                    level = "policy"
                    if (linetokens[0]=='config'):
                        writeFile(outputFile, configline)
                        continue
                    elif (linetokens[0]=='edit'):
                        # FIREWALL_POLICY name
                        auxPolicy = FIREWALL_POLICY(linetokens[1])
                        auxPolicy.natEnable = False
                    elif (linetokens[0]=='set'):
                        if (linetokens[1]=='srcintf'):
                            # FIREWALL_POLICY srcintf
                            for i in range (2,len(linetokens)):
                                    auxPolicy.srcintf.append(linetokens[i])
                        elif (linetokens[1]=='dstintf'):
                            # FIREWALL_POLICY dstintf
                            for i in range (2,len(linetokens)):
                                    auxPolicy.dstintf.append(linetokens[i])
                        elif (linetokens[1]=='srcaddr'):
                            # FIREWALL_POLICY srcaddr
                            for i in range (2,len(linetokens)):
                                    auxPolicy.srcaddr.append(linetokens[i])
                        elif (linetokens[1]=='dstaddr'):
                            # FIREWALL_POLICY dstaddr
                            """MAS COSAS PARA HACER!!!"""
                            """BUSCAR VIP o VIP GROUP"""
                            isVIP = False
                            addressExists = False
                            for vip in self.vdom.vip:
                                if (vip.name == linetokens[2]):
                                    ## ES UNA VIP! CREAR ADDRESS Y SUSTITUIR VIP CON ADDRESS
                                    isVIP = True
                                    auxPolicy.dstaddr.append(createAddrFromVIP(self,vip,newAddresses))
                            if (isVIP):
                                escribe = False
                                modConfigLine = '      ' + linetokens[0] + ' ' + linetokens[1] + ' \"' + linetokens[2].replace('\n','').replace('\"','') + vipTranslationSuffix + '\"' +'\n'
                            isVIPGRP = False
                            addrGrpExists = False
                            for vipgrp in self.vdom.vipgrp:
                                if (vipgrp.name == linetokens[2]):
                                    ## ES UN VIPGRP! CREAR ADDRGRP Y SUSTITUIR VIPGRP CON ADDRGRP
                                    isVIPGRP = True
                                    nombre = linetokens[2].replace("\"",'')
                                    for addrgrp in self.vdom.addrgrp:
                                        if (addrgrp.name == f'{nombre}{vipGrpTranslationSuffix}'):
                                            addrGrpExists = True
                                            break
                                        else:
                                            for address in self.vdom.addrgrp:
                                                if (address.name == linetokens[2]+vipGrpTranslationSuffix):
                                                    addressExists = True
                                                    break
                                    if (addrGrpExists == False):
                                        auxAddrGrp = ADDRGRP(f'\"{nombre}{vipGrpTranslationSuffix}\"')
                                        for m in vipgrp.member:
                                            auxPolicy.dstaddr.append(createAddrFromVIP (self, getVIP(self,m), newAddresses))
                                            auxAddrGrp.member.append(m+vipTranslationSuffix)
                                        newAddrGrp.append(auxAddrGrp)
                            if (isVIPGRP):
                                escribe = False
                                modConfigLine = '      ' + linetokens[0] + ' ' + linetokens[1] + ' \"' + linetokens[2].replace('\n','').replace('\"','') + vipGrpTranslationSuffix + '\"'+ '\n'
                            if ((isVIP == False) and (isVIPGRP == False)):
                                for i in range (2,len(linetokens)):
                                    auxPolicy.dstaddr.append(linetokens[i]) 
                        elif (linetokens[1]=='srcport'):
                            # FIREWALL_POLICY srcport
                            auxPolicy.srcport.append(linetokens[2])
                        elif (linetokens[1]=='dstport'):
                            # FIREWALL_POLICY dstport
                            auxPolicy.dstport.append(linetokens[2])
                        elif (linetokens[1]=='action'):
                            # FIREWALL_POLICY action
                            auxPolicy.action = linetokens[2]
                        elif (linetokens[1]=='schedule'):
                            # FIREWALL_POLICY schedule
                            auxPolicy.schedule = linetokens[2]
                        elif (linetokens[1]=='service'):
                            # FIREWALL_POLICY service
                            auxPolicy.service.append(linetokens[2])
                        elif (linetokens[1]=='nat'):
                            # FIREWALL_POLICY nat
                            auxPolicy.natEnable = True
                        elif (linetokens[1]=='ippool'):
                            # FIREWALL_POLICY ippool
                            auxPolicy.ippool = True
                        elif (linetokens[1]=='poolname'):
                            # FIREWALL_POLICY poolname
                            auxPolicy.poolname = linetokens[2]
                        elif (linetokens[1]=='name'):
                            # FIREWALL_POLICY poolname
                            auxPolicy.name = linetokens[2]
            elif len(linetokens) == 1:
                if (linetokens[0]=='next'):
                    if (level == "address"):
                        self.vdom.address.append(auxAddress)
                    elif (level == "addrgrp"):
                        self.vdom.addrgrp.append(auxAddrGrp)
                    elif (level == "vipgrp"):
                        self.vdom.vipgrp.append(auxVipgrp)
                    elif (level == "vip"):
                        self.vdom.vip.append(auxVip)
                    elif (level == "policy"):
                        self.vdom.policy.append(auxPolicy)
                elif (linetokens[0]=='end'):
                    if level == "policy":
                        writeFile(outputFile, configline)
                        escribe = False
                        generateSNAT(outputFile, self.vdom.policy)
                    level = ""
            else:
                # len(linetokens == 0), por si acaso...
                writeFile(outputFile, configline)
                continue
            if (escribe):
                writeFile(outputFile, configline)
            else:
                writeFile(outputFile, modConfigLine)
                modConfigLine = ""
        configFile.close()
        outputFile.close()

# ADDING THE EXTRA VIP AND VIPGRP       
        configFile = open(outputFileName,'r')
        outputFile = open (finalFileName,'w')
        for configline in configFile:
            if (configline.count("\"") % 2 != 0):
                writeFile(outputFile, configline)
                continue
            linetokens = shlex.split(configline)
            if len(linetokens) > 1:
                if (linetokens[0] == "config" and linetokens[1]=="firewall" and linetokens[2]=="address"):
                    writeFile(outputFile, configline)
                    for address in newAddresses:
                        writeFile(outputFile, "   edit " + address.name+"\n")
                        writeFile(outputFile, "      set subnet " + address.subnet+"\n")
                        writeFile(outputFile, "   next\n")
                    continue
                elif (linetokens[0] == "config" and linetokens[1]=="firewall" and linetokens[2]=="addrgrp"):
                    writeFile(outputFile, configline)
                    for address in newAddrGrp:
                        writeFile(outputFile, "   edit " + address.name+"\n")
                        writeFile(outputFile, "      set member") 
                        for m in address.member:
                            writeFile(outputFile," \"" + m + "\"")
                        writeFile(outputFile, "\n")
                        writeFile(outputFile, "   next\n")
                    continue
                else:
                    writeFile(outputFile, configline)
                    continue
            writeFile(outputFile, configline)
        outputFile.close()

# GENERATE THE SNAT
def generateSNAT(outputfile, policies):
    writeFile(outputfile, "config firewall central-snat-map\n")
    for policy in policies:
        if (policy.natEnable == True):
            writeFile(outputfile,"    edit 0\n")
            auxOrigAddr = ""
            for sAddr in policy.srcaddr:
                auxOrigAddr += '\"'+sAddr+'\" '
            writeFile(outputfile,"        set orig-addr " + auxOrigAddr + '\n')
            auxSIntf = ""
            for sInt in policy.srcintf:
                auxSIntf += '\"'+sInt+'\" '
            writeFile(outputfile,"        set srcintf " + auxSIntf + '\n')
            auxDstAddr = ""
            for dAddr in policy.dstaddr:
                auxDstAddr += '\"'+dAddr+'\" '
            writeFile(outputfile,"        set dst-addr " + auxDstAddr + '\n')
            auxDIntf = ""
            for dInt in policy.dstintf:
                auxDIntf += '\"'+dInt+'\" '
            writeFile(outputfile,"        set dstintf " + auxDIntf + '\n')
            if (policy.ippool==True):
                #Using IPPOOL
                writeFile(outputfile,"        set nat-ippool \"" + policy.poolname + '\"\n')
            writeFile(outputfile,"    next\n")
    writeFile(outputfile,"end\n")

def writeFile (f, configLine):
    f.write(configLine)

def getVIP(self, VIPName):
    for vip in self.vdom.vip:
        if vip.name == VIPName:
            return vip

def createAddrFromVIP(self,vip,newAddresses):
    addressExists = False
    for address in self.vdom.address:
        if (address.name == vip.name+vipTranslationSuffix):
            addressExists = True
            break
    if (addressExists == False):
        for address in newAddresses:
            if (address.name == vip.name+vipTranslationSuffix):
                addressExists = True
                break
    if (addressExists == False):
        auxAddress = ADDRESS(vip.name.replace("\"",'')+vipTranslationSuffix)
        auxAddress.subnet = vip.mappedIp + " 255.255.255.255"
        newAddresses.append(auxAddress)
    return auxAddress.name


def test_module():
    print ("Test module")
    fgt = FGT() # create an instance of FGT

if __name__ == "__main__":
    test_module()
    




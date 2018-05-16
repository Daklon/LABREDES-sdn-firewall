from netaddr import *

import csv
import ipaddress
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch


def check_netmask(SourceIp, RuleNetwork):
    print 'Checking Netmask'
    print 'Check Ip: ' + SourceIp
    print 'Check Net: ' + RuleNetwork
    myip = IPAddress(SourceIp)
    myrule = IPNetwork(RuleNetwork)
    if myip in myrule:
        return True
    else:
        return False

def check_rules(SourceIp,DestIp,Protocol,SourcePort,DestPort,SourceInterface):
    #abirmos el fichero
    with open('rules-test.txt','r') as csvfile:
        reader = csv.DictReader(csvfile)
        #recorremos el fichero comprobando si coincide con alguna de las lineas
        for row in reader:
            if row['Protocol'] == Protocol or row['Protocol'] == '' or Protocol == '':
                print ( 'Matching protocols')
                if row['SourceInterface'] == SourceInterface or row['SourceInterface'] == '' or SourceInterface == '':
                    print ( 'Matching Source Interface')
                    if check_netmask(SourceIp, row['SourceIp'])  or row['SourceIp'] == '' or SourceIp == '':
                        print ( 'Matching SourceIp')
                        if row['DestIp'] == DestIp or row['DestIp'] == '' or DestIp == '':
                            if row['SourcePort'] == SourcePort or row['SourcePort'] == '' or SourcePort == '':
                                if row['DestPort'] == DestPort or row['DestPort'] == '' or DestPort == '':
                                    if row['Action'] == 'Accept':
                                        return True
                                    else:
                                        return False

                    #si acaba el bucle sin coincidir con ninguna regla, devuelve false
        return True

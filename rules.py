import csv
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from netaddr import *
def check_rules(SourceIp,DestIp,Protocol,
                SourcePort,DestPort,SourceInterface):
                #abirmos el fichero
                with open('rules-test.txt','r') as csvfile:
                    reader = csv.DictReader(csvfile)
                    #recorremos el fichero comprobando si coincide con alguna de las lineas
                    for row in reader:
                        if row['Protocol'] == Protocol or row['Protocol'] == '' or Protocol == '':
                            if row['SourceInterface'] == SourceInterface or row['SourceInterface'] == '' or SourceInterface == '':
                                if check_netmask2(SourceIp, row['SourceIp'])  or row['SourceIp'] == '' or SourceIp == '':
                                    if row['DestIp'] == DestIp or row['DestIp'] == '' or DestIp == '':
                                        if row['SourcePort'] == SourcePort or row['SourcePort'] == '' or SourcePort == '':
                                            if row['DestPort'] == DestPort or row['DestPort'] == '' or DestPort == '':
                                                if row['Action'] == 'Accept':
                                                    return True
                                                else:
                                                    return False

                    #si acaba el bucle sin coincidir con ninguna regla, devuelve false
                    return False

def check_netmask2(SourceIp, RuleNetwork):
    myip = IPAddress(SourceIp)
    myrule = IPNetwork(RuleNetwork)
    if myip in myrule:
        return True
    else:
        return False
     
def check_netmask(SourceIp, RuleNetwork):
    if ipaddress.ip_address(SourceIp) in ipaddress.ip_interface(RuleNetwork).network:
        return True
    else:
        return False

#comprobamos si la ip en cuestion est dentro de la regla del firewall
def get_netmask(Ip):
    return ipaddress.ip_network(Ip).netmask

def get_ip(Ip):
    return ipadrress.ip_network(Ip).hostmask

def generate_match():
    match_list = []
    with open('rules-test.txt','r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['SourceInterface'] == '':
                srcInterface = None
            else:
                srcInterface = int(row['SourceInterface'])

            if row['Protocol'] == '':
                Protocol = None
            elif row['Protocol'] == 'TCP':
                Protocol = 6
                Udp_src = None
                Udp_dst = None
                if row['SourcePort'] == '':
                    Tcp_src = None
                else:
                    Tcp_src = int(row['SourcePort'])

                if row['DestPort'] == '':
                    Tcp_dst = None
                else:
                    Tcp_dst = int(row['DestPort'])

            elif row['Protocol'] == 'UDP':
                Protocol = 17
                Tcp_src = None
                Tcp_dst = None
                if row['SourcePort'] == '':
                    Udp_src = None
                else:
                    Udp_src = int(row['SourcePort'])

                if row['DestPort'] == '':
                    Udp_dst = None
                else:
                    Udp_dst = int(row['DestPort'])

            if row['DestIp'] == '':
                DestIp = None
            else:
                DestIp = row['DestIp']

            if row['SourceIp'] == '':
                SourceIp = None
            else:
                SourceIp = row['SourceIp']

            match = OFPMatch(in_phy_port=srcInterface, ip_proto=Protocol, ipv4_src=SourceIp, ipv4_dst=DestIp, tcp_src=Tcp_src, tcp_dst=Tcp_dst, udp_src=Udp_src, udp_dst=Udp_dst)
            match_list.append(match)

    return match_list

#print (generate_match())
print (check_rules('192.168.0.3','192.168.0.2','TCP','22','337788','2'))

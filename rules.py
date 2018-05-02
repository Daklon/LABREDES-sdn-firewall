import csv
import ipaddress

def check_rules(SourceIp,DestIp,Protocol,
                SourcePort,DestPort,SourceInterface,DestInterface):
                #abirmos el fichero
                with open('rules-test.txt','r') as csvfile:
                    reader = csv.DictReader(csvfile)
                    #recorremos el fichero comprobando si coincide con alguna de las líneas
                    for row in reader:
                        if row['Protocol'] == Protocol or row['Protocol'] == '' or Protocol == '':
                            if row['SourceInterface'] == SourceInterface or row['SourceInterface'] == '' or SourceInterface == '':
                                if row['DestInterface'] == DestInterface or row['DestInterface'] == '' or DestInterface == '':
                                    if check_netmask(SourceIp, row['SourceIp'])  or row['SourceIp'] == '' or SourceIP == '':
                                        if row['DestIp'] == DestIp or row['DestIp'] == '' or DestIp == '':
                                            if row['SourcePort'] == SourcePort or row['SourcePort'] == '' or SourcePort == '':
                                                if row['DestPort'] == DestPort or row['DestPort'] == '' or DestPort == '':
                                                    return True

                    #si acaba el bucle sin coincidir con ninguna regla, devuelve false
                    return False

#comprobamos si la ip en cuestión está dentro de la regla del firewall
def check_netmask(SourceIp, RuleNetwork):
    if ipaddress.ip_address(SourceIp) in ipaddress.ip_interface(RuleNetwork).network:
        return True
    else:
        return False

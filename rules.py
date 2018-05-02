import csv

def check_rules(SourceIp,DestIp,Protocol,
                SourcePort,DestPort,SourceInterface,DestInterface):
                #abirmos el fichero
                with open('rules-test.txt','r') as csvfile:
                    reader = csv.DictReader(csvfile)
                    #recorremos el fichero comprobando si coincide con alguna de las líneas
                    for row in reader:
                        if row['Protocol'] == Protocol or row['Protocol'] == '':
                            if row['SourceInterface'] == SourceInterface or row['SourceInterface'] == '':
                                if row['DestInterface'] == DestInterface or row['DestInterface'] == '':
                                    if row['SourceIp'] == SourceIp or row['SourceIp'] == '':
                                        if row['DestIp'] == DestIp or row['DestIp'] == '':
                                            if row['SourcePort'] == SourcePort or row['SourcePort'] == '':
                                                if row['DestPort'] == DestPort or row['DestPort'] == '':
                                                    return True

                    #si acaba el bucle sin coincidir con ninguna regla, devuelve false
                    return False
                       

if(check_rules('3.3.3.3','','','','','','')):
    print("Pasa")
else:
    print("No Pasa")

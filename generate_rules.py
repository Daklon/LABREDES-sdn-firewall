#-----------------------------------------------------------------------------------
# This small script generate the rules-test.txt file structure with a small example
#------------------------------------------------------------------------------------
import csv

with open('rules-test.txt', 'w') as csvfile:
    fieldnames = ['SourceIp','DestIp','Protocol','SourcePort','DestPort','SourceInterface','DestInterface']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow({'SourceIp':'1.1.1.1','DestIp':'2.2.2.2','Protocol':'TCP','SourcePort':'80','DestPort':'80','SourceInterface':'eth1','DestInterface':'eth2'})

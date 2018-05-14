#-----------------------------------------------------------------------------------
# This small script generate the rules-test.txt file structure with a small example
#------------------------------------------------------------------------------------
import csv

with open('rules-test.txt', 'w') as csvfile:
    fieldnames = ['SourceIp','DestIp','Protocol','SourcePort','DestPort','SourceInterface','DestInterface']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow({'SourceIp':'1.1.1.0/24','DestIp':'2.2.2.2/24','Protocol':'TCP','SourcePort':'80','DestPort':'80','SourceInterface':'1','DestInterface':'2'})

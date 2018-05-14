
class AssignmentIP_Mac:

	def __init__(self,ip,mac):
           self.IP_=[]
           self.Mac_=[]

           aux=ip.split('.')
           for x in range(4):
	      self.IP_.append(int(aux[x]))

           aux=mac.split(':')
	   for x in range(6):
	      self.Mac_.append(int(aux[x], 16))

        def incrementar_IP(self):
           for k in [3,2,1,0]:
              if(self.IP_[k]<255):
                 self.IP_[k]=self.IP_[k]+1
		 for z in range(3-k):
                    self.IP_[3-z]=0
                 return '.'.join(str(x) for x in self.IP_)
      
           return "No hay direcciones disponibles"

        def incrementar_Mac(self):
           for k in [5,4,3,2,1,0]:
              if(self.Mac_[k]<255):
                 self.Mac_[k]=self.Mac_[k]+1
		 for z in range(5-k):
                    self.Mac_[5-z]=0
                 return ':'.join(str(format(x,'02x')) for x in self.Mac_)
      
           return "No hay direcciones disponibles"
             

'''
ip="200.160.0.0"
mac="1c:ff:01:77:00:00"
x=AssignmentIP_Mac(ip,mac)

for k in range(300):
   print(x.incrementar_IP())

for k in range(300):
   print(x.incrementar_Mac())
'''


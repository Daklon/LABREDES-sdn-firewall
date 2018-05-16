
class ipmac:

    def __init__(self,ip,mac):
        self.Ip_ = []
        self.Mac_ = []

        aux=ip.split('.')
        for x in range(4):
            self.Ip_.append(int(aux[x]))

        aux=mac.split(':')
        for x in range(6):
            self.Mac_.append(int(aux[x], 16))

    def incrementar_Ip(self):
        for k in [3,2,1,0]:
            if(self.Ip_[k]<255):
                self.Ip_[k]=self.Ip_[k]+1
                for z in range(3-k):
                    self.Ip_[3-z]=0
                return '.'.join(str(x) for x in self.Ip_)

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
x=AssignmentIp_Mac(ip,mac)

for k in range(300):
   print(x.incrementar_Ip())

for k in range(300):
   print(x.incrementar_Mac())
'''

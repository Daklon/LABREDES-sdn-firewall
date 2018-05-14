from mininet.net import Mininet
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.node import OVSSwitch, Controller, RemoteController
from functools import partial
#definimos dos controladores(revisar)
c0 = RemoteController('c0', ip='192.168.1.37', port=6632)
c1 = RemoteController('c1', ip='192.168.1.37', port=6633)
#decidimo que controlador usa cada switch
cmap = {'s1': c0, 's2':c0, 's3':c1}
#define MultiSwitch

class MultiSwitch ( OVSSwitch ):
	def start(self, controllers):
		return OVSSwitch.start(self, [cmap[self.name]])

#definimos la topologia
class BasicTopo ( Topo ):
	def __init__(self):
		#initialize topology
		Topo.__init__(self)
		#Add hosts and switches
		leftHost1 = self.addHost('h1')
		leftHost2 = self.addHost('h2')
		leftSwitch = self.addSwitch('s1')

		rightHost1 = self.addHost('h3')
		rightHost2 = self.addHost('h4')
		rightSwitch = self.addSwitch('s2')

		CustomSwitch = self.addSwitch('s3')
		#Add links
		self.addLink(leftHost1, leftSwitch)
		self.addLink(leftHost2, leftSwitch)
		self.addLink(rightHost1, rightSwitch)
		self.addLink(rightHost2, rightSwitch)
		self.addLink(leftSwitch, CustomSwitch)
		self.addLink(rightSwitch, CustomSwitch)

#la creamos
topos = BasicTopo()
#creamos un objeto mininet

#esto es para la 1.3 de openflow
#switch= partial( MultiSwitch, protocols='OpenFLow13')

#net = Mininet(topo=topos, switch=switch, build = False)
net = Mininet(topo=topos, switch=MultiSwitch, build=False)
#annadimos los controladores a la simulacion de red
#net.addController(c0)
#net.addController(c1)

#construimos
net.build()

#establecemos ips
h1 = net.get('h1')
h2 = net.get('h2')
h3 = net.get('h3')
h4 = net.get('h4')

h1.setIP('192.168.0.2')
h2.setIP('192.168.0.3')
h3.setIP('192.168.1.2')
h4.setIP('192.168.1.3')


#iniciamos
net.start()
#hacemos pingall
net.pingAll()
#consola
CLI(net)
#paramos
net.stop

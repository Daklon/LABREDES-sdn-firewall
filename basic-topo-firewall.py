from mininet.net import Mininet
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.node import OVSSwitch, Controller, RemoteController
#definimos dos controladores(revisar)
#c0 = Controller('c0', port=6633)
c1 = RemoteController('c1', ip='10.209.2.81' ,port=6633)
#decidimo que controlador usa cada switch
cmap = {'s1': c1, 's2':c1, 's3':c1}
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
net = Mininet(topo=topos, switch=MultiSwitch, build = False)
#annadimos los controladores a la simulacion de red
#net.addController(c0)
net.addController(c1)
#construimos
net.build()
#iniciamos
net.start()
#consola
CLI(net)
#paramos
net.stop

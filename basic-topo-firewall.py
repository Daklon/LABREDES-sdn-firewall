from mininet.net import Mininet
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.node import OVSSwitch, Controller, RemoteController
from functools import partial
#definimos dos controladores(revisar)
c0 = RemoteController('c0', ip='192.168.1.37', port=6632)
c1 = RemoteController('c1', ip='10.150.14.156', port=6633)
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

#establecemos ips y/o MACS
h1 = net.get('h1')
h2 = net.get('h2')
h3 = net.get('h3')
h4 = net.get('h4')
s1 = net.get('s1')
s2 = net.get('s2')
s3 = net.get('s3')


h1.setIP('192.168.0.2')
h1.setMAC('00:00:00:00:00:01')
h2.setIP('192.168.0.3')
h2.setMAC('00:00:00:00:00:02')
h3.setIP('192.168.1.2')
h3.setMAC('00:00:00:00:00:03')
h4.setIP('192.168.1.3')
h4.setMAC('00:00:00:00:00:04')

s1.setMAC('00:AA:00:AA:01:01','s1-eth1')
s1.setMAC('00:AA:00:AA:01:02','s1-eth2')
s1.setMAC('00:AA:00:AA:01:03','s1-eth3')

s2.setMAC('00:AA:00:AA:02:01','s2-eth1')
s2.setMAC('00:AA:00:AA:02:02','s2-eth2')
s2.setMAC('00:AA:00:AA:02:03','s2-eth3')

s3.setMAC('00:AA:00:AA:03:01','s3-eth1')
s3.setMAC('00:AA:00:AA:03:02','s3-eth2')


#iniciamos
net.start()
#hacemos pingall
#net.pingAll()
#establecemos gateway y rutas
h1.cmd('route del -net 192.0.0.0 gw 0.0.0.0 netmask 255.0.0.0 dev h1-eth0')
h1.cmd('route add -net 192.168.0.0 netmask 255.255.255.0 dev h1-eth0')
h1.cmd('route add default gw 192.168.0.1 netmask 255.255.255.0 dev h1-eth0')

h2.cmd('route del -net 192.0.0.0 gw 0.0.0.0 netmask 255.0.0.0 dev h2-eth0')
h2.cmd('route add -net 192.168.0.0 netmask 255.255.255.0 dev h2-eth0')
h2.cmd('route add default gw 192.168.0.1 netmask 255.255.255.0 dev h2-eth0')

h3.cmd('route del -net 192.0.0.0 gw 0.0.0.0 netmask 255.0.0.0 dev h3-eth0')
h3.cmd('route add -net 192.168.1.0 netmask 255.255.255.0 dev h3-eth0')
h3.cmd('route add default gw 192.168.1.1 netmask 255.255.255.0 dev h3-eth0')

h4.cmd('route del -net 192.0.0.0 gw 0.0.0.0 netmask 255.0.0.0 dev h4-eth0')
h4.cmd('route add -net 192.168.1.0 netmask 255.255.255.0 dev h4-eth0')
h4.cmd('route add default gw 192.168.1.1 netmask 255.255.255.0 dev h4-eth0')

#consola
CLI(net)
#paramos
net.stop

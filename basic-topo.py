
from mininet.topo import Topo
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

topos = {'basictopo':(lambda:BasicTopo())}

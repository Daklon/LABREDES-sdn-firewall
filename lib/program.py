from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
#from lib.AssignmentIP_Mac import AssignmentIP_Mac

baseIP  = '192.168.0.0'
baseMAC = '00:00:00:00:00:00'

class AssignmentIP_Mac:

    def __init__(self,ip,mac):
        self.IP_= []
        self.Mac_= []

        aux = ip.split('.')
        for x in range(4):
            self.IP_.append(int(aux[x]))

        aux = mac.split(':')
        for x in range(6):
            self.Mac_.append(int(aux[x],16))

    def incrementar_IP(self):
        for k in [3,2,1,0]:
            if(self.IP_[k]<255):
                self.IP_[k]=self.IP_[k]+1
                for z in range(3-k):
                    self.IP_[3-z]=0
                return '.'.join(str(x) for x in self.IP_)

    def incrementar_Mac(self):
        for k in [5,4,3,2,1,0]:
            if(self.Mac_[k] < 255):
                self.Mac_[k]=self.Mac_[k]+1
                for z in range(5-k):
                    self.Mac_[5-z]=0
                return ':'.join(str(format(x,'02x')) for x in self.Mac_)




class L2Switch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(L2Switch, self).__init__(*args, **kwargs)
                self.ip_mac_gen    = AssignmentIP_Mac(baseIP, baseMAC)
                self.pckt_queue    = []
                self.port_mac_ip   = {}
                self.address_cache = {}

        def add_flow(self,datapath, inMatch, inAction, tableId):
            ofproto = datapath.ofproto
            ofproto_parser = datapath.ofproto_parser

            # inst = [ofproto_parser.OFPInstructionActions(1)]
            # inst = [ofproto_parser.OF1PInstructionGotoTable(1)]
            # si no se acepta es None
            
            # match si es None 
            mod = datapath.ofproto_parser.OFPFlowMod(datapath, table_id = tableId, command = ofproto.OFPFC_ADD,  
                                                     match=inMatch, instructions=inst)
            datapath.send_msg(mod)

            #mod = datapath.ofproto_parser.OFPFlowMod(datapath, cookie=0, cookie_mask=0, table_id, 
            #                                         command, timeout, hard_timeout=0 priority=32768,
            #                                         buffer_id=4294967295, out_port=0, out_group=0, flags=0, 
            #                                         importance=0, match=None, instructions=None)
            #
            # datapath: Identifica el switch al que se le va a modificar la tabla de flujo
            # cookie y cookie_mask no los vamos a usar
            # table_id: Identifica la tabla del switch que se va a modificar
            # command: operacion que se realiza sobre el flujo, En nuestro caso solo se va a anyadir OFPFC_ADD
            # match Que criterios se van a aplicar a la tabla
            # instructions 
            
            
        def genArpMessage(self, dstMac, dstIp, srcMac, srcIp, op):
            if op == 1:
                arpDstMac = '00:00:00:00:00:00'
            else:
                arpDstMac = dstMac

            e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(hwtype=1, proto=0x800, hlen=6, plen=4, opcode=op, 
                        src_mac=srcMac, src_ip=srcIp, dst_mac=dstMac, dst_ip=dstIp)

            msg = packet.packet()
            msg.add_protocol(e)
            msg.add_protocol(a)
            msg_serialize()
            return msg

        def processArp(self, arp_pckt, srcMac, srcIp, in_port):
            if (arp_pckt.dst_ip == srcIp): 
                if (arp_pckt.opcode == 1):
                    print 'Its an arp request' #debug
                    #Its an arp request from a host
                    msg = genArpMessage(arp_pckt.src_mac, arp_pckt.src_ip, srcMac, srcIp, 2)
                    return msg
                else:
                    print 'its an arp reply, sending pending packages' #debug
                    # It's an arp reply
                    # check in the packet queue if there are any packets waiting to be released
                    for pckt in pckt_queue:
                        ip = pckt.get_protocol(ipv4.ipv4)
                        if ip.dst == arp_pckt.src_ip:
                            print 'Pending package sent' #debug
                            #send_pckt(pckt)
                            pckt_queue.remove(pckt)
                    return None


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
                msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		ofp_parser = dp.ofproto_parser


                #Read the switch port number that sent the message to the controller
                in_port = msg.in_port
                print 'received a message from port'+ str(port) #debug

                #Check if the port already has an IP, if it doesnt a new MAC-IP pair will be assigned to it
                if in_port not in self.port_mac_ip.keys():
                    newIP  = self.ip_mac_gen.incrementar_IP
                    newMAC = self.ip_mac_gen.incrementar_Mac
                    self.port_mac_ip[in_port]= {'mac': newMAC, 'ip': newIP}
                    print 'added new key ' #debug
                    print self.port_mac_ip[in_port] #debug


                #Read the packet received from the switch to extract the information
                pkt = packet.Packet(msg.data)

                #Read the ethernet header
                eth = pkt.get_protocol(ethernet.ethernet)
                dstMac = eth.dst
                srcMac = eth.src

                #Check for ARP header
                arp = pkt.get_protocol(arp.arp)
                if arp is not None:
                    print 'The packet is an arp protocol message' #debug
                    sourceMac = self.port_mac_ip[in_port]['mac']
                    sourceIp  = self.port_mac_ip[in_port]['ip']
                    arp_msg = processArp(arp,sourceMac, sourceIp)
                    if arp_msg is not None:
                        action = ofp_parser[OFPActionOutput(in_port)]
                        out = ofp_parser.OFPPacketOut(datapath=dp, actions=action, data=arp_msg)
                        dp.send_msg(out)

                else:
                    ip = pkt.get_protocol(ipv4,ipv4)

                    #checking our direction tables to update it
                    if ip.src not in self.address_cache.keys():
                        self.address_cache[ip.src] = {'mac':srcMac, 'port':in_port}
                        print 'New direction added to the table ' #debug
                        print address_cache[ip.src] #debug

                    #checking if we know how to get to the destination, if we dont an arp request will be sent, and the packet will
                     #be added to the queue
                    if ip.dst not in self.address_cache.keys():
                        for port in self.port_mac_ip.keys():
                            portIp  = self.port_mac_ip[port]['ip']
                            portMac = self.port_mac_ip[port]['mac']
                            # If possible i would like to substitute with a method
                            msg = genArpMessage('ff:ff:ff:ff:ff:ff', ip.dst, portIp, portMac)
                            action = [ofp_parser.OFPActionOutput(port)]
                            out = ofp_parser.OFPPacketOut(datapath=dp,actions=action,data=msg)
                            dp.send_msg(out)
                            #send_msg()

                    else:
                        print 'Checking rules'
                        #Check for rules

                    #Stablish relation between MAC and Port


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from AssignmentIP_Mac import ipmac
from netaddr import *

import csv
import ipaddress
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch

baseIP  = '192.168.0.10'
baseMAC = '00:00:00:00:00:10'


def check_netmask(SourceIp, RuleNetwork):
    myip = IPAddress(SourceIp)
    myrule = IPNetwork(RuleNetwork)
    if myip in myrule:
        return True
    else:
        return False

def check_rules(SourceIp,DestIp,Protocol,SourcePort,DestPort,SourceInterface):
    #abirmos el fichero
    with open('rules-test.txt','r') as csvfile:
        reader = csv.DictReader(csvfile)
        #recorremos el fichero comprobando si coincide con alguna de las lineas
        for row in reader:
            if row['Protocol'] == Protocol or row['Protocol'] == '' or Protocol == '':
                print ( 'Matching protocols')
                if row['SourceInterface'] == SourceInterface or row['SourceInterface'] == '' or SourceInterface == '':
                    print ( 'Matching Source Interface')
                    if check_netmask(SourceIp, row['SourceIp'])  or row['SourceIp'] == '' or SourceIp == '':
                        print ( 'Matching SourceIp')
                        if row['DestIp'] == DestIp or row['DestIp'] == '' or DestIp == '':
                            if row['SourcePort'] == SourcePort or row['SourcePort'] == '' or SourcePort == '':
                                if row['DestPort'] == DestPort or row['DestPort'] == '' or DestPort == '':
                                    if row['Action'] == 'Accept':
                                        return True
                                    else:
                                        return False

                    #si acaba el bucle sin coincidir con ninguna regla, devuelve false
        return True

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.ip_mac_gen    = ipmac(baseIP, baseMAC)
        self.pckt_queue    = []
        self.port_mac_ip   = {}
        self.address_cache = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print ( 'Conectado')
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER )]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,priority=0,match=match,instructions=inst)
        datapath.send_msg(mod)

    def genArpMessage(self, dstMac, dstIp, srcMac, srcIp, op):
        if op == 1:
            arpDstMac = '00:00:00:00:00:00'
        else:
            arpDstMac = dstMac

        e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=op,
                    src_mac=srcMac, src_ip=srcIp, dst_mac=arpDstMac, dst_ip=dstIp)

        msg = packet.Packet()
        msg.add_protocol(e)
        msg.add_protocol(a)
        msg.serialize()
        return msg

    def processArp(self, arp_pckt, srcMac, srcIp, in_port, dp):
        if (arp_pckt.opcode == 1):
            print ( 'Its an arp request') #debug
            #Its an arp request from a host
            msg = self.genArpMessage(arp_pckt.src_mac, arp_pckt.src_ip, srcMac, srcIp, 2)
            return msg
        else:
            print ( 'its an arp reply, sending pending packages') #debug
            # It's an arp reply
            self.address_cache[arp_pckt.src_ip] = {'mac':arp_pckt.src_mac,'port':in_port}
            # check in the packet queue if there are any packets waiting to be released

            for pckt in self.pckt_queue:
                pkt = packet.Packet(pckt.data)
                ip = pkt.get_protocol(ipv4.ipv4)
                ar = pkt.get_protocol(arp.arp)
                if (ip is not None):
                    if (ip.dst == arp_pckt.src_ip):
                        print ( 'Pending package sent') #debug
                        actions = [dp.ofproto_parser.OFPActionOutput(self.address_cache[ip.dst]['port'])]
                        out = dp.ofproto_parser.OFPPacketOut(datapath=dp,buffer_id=dp.ofproto.OFP_NO_BUFFER, in_port=dp.ofproto.OFPP_CONTROLLER, actions=actions, data=pckt.data)
                        dp.send_msg(out)
                        dp.send_msg(pckt)
                        self.pckt_queue.remove(pckt)
                else:
                    if (ar is not None):
                        if (ar.dst_ip == arp_pckt.src_ip):
                            print ( 'Pending package sent') #debug
                            dp.send_msg(pckt)
                            self.pckt_queue.remove(pckt)

            return None


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        in_port = msg.match['in_port']
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        #---------------------------------------------------------------------------
        print  '---------------------------------------------------------------------------'
        print  'received a message from port' + str(in_port) #debug

        #Check if the port already has an IP, if it doesnt a new MAC-IP pair will be assigned to it
        if in_port not in self.port_mac_ip.keys():
            newIP  = self.ip_mac_gen.incrementar_Ip()
            newMAC = self.ip_mac_gen.incrementar_Mac()
            self.port_mac_ip[in_port]= {'mac': newMAC, 'ip': newIP}
            print  'added new key ' #debug
            print self.port_mac_ip[in_port] #debug



        #Read the packet received from the switch to extract the information
        pkt = packet.Packet(msg.data)

        #Read the ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        dstMac = eth.dst
        srcMac = eth.src

        #Check for ARP header
        a = pkt.get_protocol(arp.arp)
        if a is not None:
            print  '\nThe packet is an arp protocol message\n' #debug
            sourceMac = self.port_mac_ip[in_port]['mac']
            sourceIp  = self.port_mac_ip[in_port]['ip']
            if (a.dst_ip == sourceIp):
                arp_msg = self.processArp(a,sourceMac, sourceIp, in_port, dp)
                if arp_msg is not None:
                    data = None
                    if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    action = [ofp_parser.OFPActionOutput(in_port)]
                    out = ofp_parser.OFPPacketOut(datapath=dp,buffer_id=msg.buffer_id, in_port=ofp.OFPP_CONTROLLER, actions=action, data=arp_msg)
                    dp.send_msg(out)
            else:
                if a.dst_ip in self.address_cache.keys():
                    data = msg.data
                    port = self.address_cache[a.dst_ip]['port']
                    action = [ofp_parser.OFPActionOutput(port)]
                    out = ofp_parser.OFPPacketOut(datapath=dp,buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=action,data=data)
                    dp.send_msg(out)
                else:
                    for port in self.port_mac_ip.keys():
                        portIp  = self.port_mac_ip[port]['ip']
                        portMac = self.port_mac_ip[port]['mac']
                        print portIp + ' ' + portMac #debug
                        self.pckt_queue.append(msg)
                        # If possible i would like to substitute with a method
                        n_msg = self.genArpMessage('ff:ff:ff:ff:ff:ff', a.dst_ip, portMac, portIp,1)
                        action = [ofp_parser.OFPActionOutput(port)]
                        out = ofp_parser.OFPPacketOut(datapath=dp,buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=action,data=n_msg.data)
                        dp.send_msg(out)


                # data = None
                # if msg.buffer_id == ofp.OFP_NO_BUFFER:
                #     data = msg.data
                # action = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                # out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=ofp.OFPP_CONTROLLER, actions=action, data=data)
                # dp.send_msg(out)


        else:
            print  'extracting IVP4 protocol'
            ip = pkt.get_protocol(ipv4.ipv4)

            print self.address_cache.keys()
            #checking our direction tables to update it
            if ip.src not in self.address_cache.keys():
                self.address_cache[ip.src] = {'mac':srcMac, 'port':in_port}
                print 'New direction added to the table ' #debug
                print self.address_cache[ip.src] #debug

            else:
                print  'Source IP Known \n\n'
            #checking if we know how to get to the destination, if we dont an arp request will be sent, and the packet will
             #be added to the queue
            if ip.dst not in self.address_cache.keys():
                print  'Unknown destination' #debug
                for port in self.port_mac_ip.keys():
                    portIp  = self.port_mac_ip[port]['ip']
                    portMac = self.port_mac_ip[port]['mac']
                    print portIp
                    print portMac
                    self.pckt_queue.append(msg)
                    # If possible i would like to substitute with a method
                    n_msg = self.genArpMessage('ff:ff:ff:ff:ff:ff', ip.dst, portMac, portIp,1)
                    action = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                    out = ofp_parser.OFPPacketOut(datapath=dp,buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=action,data=n_msg.data)
                    dp.send_msg(out)
                    #send_msg()

            else:
                print  'Checking rules'
                port = self.address_cache[ip.dst]['port']
                data = msg.data

                if ip.proto == 0x06:
                    tcpp = pkt.get_protocol(tcp.tcp)
                    src_port = tcpp.src_port
                    dst_port = tcpp.dst_port
                    protocol = 'TCP'

                elif ip.proto == 0x17:
                    udpp = pkt.get_protocol(udp.udp)
                    src_port = udpp.src_port
                    dst_port = udpp.dst_port
                    protocol = 'UDP'

                else:
                    src_port = None
                    dst_port = None
                    protocol = ''
                print ip.src + ' ' + ip.dst + ' ' + protocol + ' ' + str(src_port) + ' ' + str(dst_port) + ' ' + str(in_port)
                if(check_rules(ip.src, ip.dst, protocol, str(src_port), str(dst_port), str(in_port))):
                    if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    print  'Packet accepted!!'
                    action = [ofp_parser.OFPActionOutput(port)]
                    out = ofp_parser.OFPPacketOut(datapath=dp,buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=action,data=data)
                    dp.send_msg(out)
        #------------------------------------------------------------------------------------
        # actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        #
        # data = None
        # if msg.buffer_id == ofp.OFP_NO_BUFFER:
        #     data = msg.data
        #
        # out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        # dp.send_msg(out)

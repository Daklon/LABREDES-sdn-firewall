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
from netaddr import *
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from rules import *



class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.routing_table = {'192.168.0.0/24': 1, '192.168.1.0/24':2}
        self.pckt_queue    = []
        self.port_mac_ip   = {  1: {'mac': '00:00:00:00:00:11', 'ip': '192.168.0.1'},
                                2: {'mac': '00:00:00:00:00:12', 'ip': '192.168.1.1'}}
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

    def send_msg(self, dtp, message, actions):
        print actions
        ofproto = dtp.ofproto
        buffer_id = ofproto.OFP_NO_BUFFER
        in_port = ofproto.OFPP_CONTROLLER
        out = dtp.ofproto_parser.OFPPacketOut(datapath=dtp, buffer_id=buffer_id, in_port=in_port, actions=actions, data = message.data)
        dtp.send_msg(out)

    def generate_comparable(self, ip_pckt, msg, in_port):
        port = self.address_cache[ip_pckt.dst]['port']
        data = msg.data
        pkt = packet.Packet(msg.data)

        if ip_pckt.proto == 0x06:
            tcpp = pkt.get_protocol(tcp.tcp)
            src_port = tcpp.src_port
            dst_port = tcpp.dst_port
            protocol = 'TCP'

        elif ip_pckt.proto == 0x17:
            udpp = pkt.get_protocol(udp.udp)
            src_port = udpp.src_port
            dst_port = udpp.dst_port
            protocol = 'UDP'

        else:
            src_port = None
            dst_port = None
            protocol = ''
        compare = { 'SourceIp': ip_pckt.src, 'DestIp': ip_pckt.dst, 'Protocol': protocol ,'SourcePort': str(src_port), 'DestPort': str(dst_port), 'SourceInterface': str(in_port) }
        print compare
        return compare


# ------------------------------- CORRECT ---------------------------------------------------
    def genArpMessage(self, dstMac, dstIp, srcMac, srcIp, op):
        print 'Message generated'
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
# ------------------------------- CORRECT ---------------------------------------------------

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
                        print ( 'Pending package sent\n') #debug
                        print 'IP_SRC: ' + ip.src
                        print 'IP_DST: ' + ip.dst

                        port_out = self.address_cache[ip.dst]['port']
                        print 'PORTOUT: ' + str(port_out)
                        mac = self.port_mac_ip[port_out]['mac']
                        mac_dst = self.address_cache[ip.dst]['mac']
                        actions = [ dp.ofproto_parser.OFPActionSetField(eth_src=mac),
                                    dp.ofproto_parser.OFPActionSetField(eth_dst=mac_dst),
                                    dp.ofproto_parser.OFPActionDecNwTtl(),
                                    dp.ofproto_parser.OFPActionOutput(port_out)]
                        self.send_msg(dp, pckt, actions)
                        self.pckt_queue.remove(pckt)
                else:
                    if (ar is not None):
                        if (ar.dst_ip == arp_pckt.src_ip):
                            print ( 'Pending package sent') #debug
                            port_out = self.address_cache[ar.dst_ip]['port']
                            mac = self.port_mac_ip[port_out]['mac']
                            mac_dst = self.address_cache[ar.dst_ip]['mac']
                            actions = [ dp.ofproto_parser.OFPActionSetField(eth_src=mac),
                                        dp.ofproto_parser.OFPActionSetField(eth_dst=mac_dst),
                                        dp.ofproto_parser.OFPActionDecNwTtl(),
                                        dp.ofproto_parser.OFPActionOutput(port_out)]
                            self.send_msg(dp, pckt, actions)
                            self.pckt_queue.remove(pckt)

            return None


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print self.address_cache
        msg = ev.msg
        dp = msg.datapath

        in_port = msg.match['in_port']
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        #---------------------------------------------------------------------------
        print  '---------------------------------------------------------------------------'
        print  'received a message from port' + str(in_port) #debug

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
                    print 'Sending ARP reply'
                    action = [ofp_parser.OFPActionOutput(in_port)]
                    self.send_msg(dp, arp_msg, action)
# ------------------------------- CORRECT ---------------------------------------------------
        else:
            print  'extracting IVP4 protocol'
            ip = pkt.get_protocol(ipv4.ipv4)

            print self.address_cache.keys()
            #checking our direction tables to update it
            if ip.src not in self.address_cache.keys():
                self.address_cache[ip.src] = {'mac':srcMac, 'port':in_port}
                print 'New direction added to the table ' #debug
                print self.address_cache[ip.src] #debug
                print self.address_cache
            else:
                print  'Source IP Known \n\n' #debug, useless print
            #checking if we know how to get to the destination, if we dont an arp request will be sent, and the packet will
             #be added to the queue
# ------------------------------- CORRECT ---------------------------------------------------
            if ip.dst not in self.address_cache.keys():
                print  'Unknown destination' #debug

                print self.routing_table
                for ip_net in self.routing_table.keys():
                    if check_netmask(ip.dst, ip_net):
                        print 'Match'
                        port = self.routing_table[ip_net]
                        portIp = self.port_mac_ip[port]['ip']
                        portMac = self.port_mac_ip[port]['mac']
                        print 'IP: ' + str(portIp)
                        print 'MAC: ' + str(portMac)
                        print 'PORT: ' + str(port)

                        self.pckt_queue.append(msg)
                        n_msg = self.genArpMessage('ff:ff:ff:ff:ff:ff', ip.dst, portMac, portIp,1)
                        action = [ofp_parser.OFPActionOutput(port)]
                        out = ofp_parser.OFPPacketOut(datapath=dp,buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=action,data=n_msg.data)
                        dp.send_msg(out)
# ------------------------------- CORRECT ---------------------------------------------------
            else:
                print  'Checking rules'
                port = self.address_cache[ip.dst]['port']
                comp = self.generate_comparable(ip, msg, in_port)
                print comp
                if(check_rules(comp['SourceIp'], comp['DestIp'], comp['Protocol'], comp['SourcePort'], comp['DestPort'], comp['SourceInterface'])):
                    print  'Packet accepted!!'
                    mac = self.port_mac_ip[port]['mac']
                    mac_dst = self.address_cache[ip.dst]['mac']
                    print 'src_mac = ' + mac
                    action = [  ofp_parser.OFPActionSetField(eth_src=mac),
                                ofp_parser.OFPActionSetField(eth_dst=mac_dst),
                                ofp_parser.OFPActionDecNwTtl(),
                                ofp_parser.OFPActionOutput(port)]
                    # m = msg.match['ipv4_dst']
                    # print m
                    self.send_msg(dp, msg, action)

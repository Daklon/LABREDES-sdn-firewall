from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0

BASE_MAC_ADDRESS = 0
class 

def newIp(num):



class L2Switch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(L2Switch, self).__init__(*args, **kwargs)
                self.mac_to_port = {} 
                self.port_to_ip = {}
                self.port_to_mac = {}

        def add_rules_flow():
            #mod = datapath.ofproto_parser(datapath, cookie=0, cookie_mask=0, table_id, command, timeout, hard_timeout=0 priority=32768,
            #                              buffer_id=4294967295, out_port=0, out_group=0, flags=0, importance=0, match=None, 
            #                              instructions=None)
            #
            # datapath: Identifica el switch al que se le va a modificar la tabla de flujo
            # cookie y cookie_mask no los vamos a usar
            # table_id: Identifica la tabla del switch que se va a modificar
            # command: 
            
            
        def add_conms_flow():



	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		ofp_parser = dp.ofproto_parser


                #Read the switch port number that sent the message to the controller
                in_port = msg.in_port

                #Check if the port already has an IP, if it doesnt a new MAC
                if self.port_to_ip[in_port] is None:
                    #Assign new Ip to designated port

                #Check if the port already has a MAC, if it doesnt a new MAC will be Assigned
                if self.port_to_mac[in_port] is None:
                    #Assign new Ip to designated port

                switchMac = self.port_to_mac[in_port]
                switchIp = self.port_to_ip[in_port]

                #Read the packet received from the switch to extract the information
                pkt = packet.Packet(msg.data)

                #Read the ethernet header
                eth = pkt.get_protocol(ethernet.ethernet)
                dstMac = eth.dst
                srcMac = eth.src

                #Check for ARP header
                arp = pkt.get_protocol(arp.arp)
                if arp is not None:
                    processArp(arp)

                #Check for rules

                #Stablish relation between MAC and Port

                if self.mac_to_port[srcMac] is None:
                    #insert into the Switching flow mac & in_port
                    #insert into local dictionary
                    self.mac_to_port[srcMac] = in_port

		#actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
		#out = ofp_parser.OFPPacketOut(
			#datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,actions=actions)
		#dp.send_msg(out)

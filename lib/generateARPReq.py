from ryu.ofproto import ether
from ryu.lib.packet import ethernet, arp, packet

def genArpRequest(srcMac, srcIp, dstIp)
    
    e = ethernet.ethernet(  dst='ff:ff:ff:ff:ff:ff',
                            src=srcMac,
                            ethertype=ether.ETH_TYPE_ARP)
    a = arp.arp( hwtype=1 ,proto=0x0800, hlen=6, plen=4, opcode = 1,
                 src_mac = srcMac, src_ip = srcIp,
                 dst_mac = "00:00:00:00:00:00"
                 dst_ip = dstIp)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    print repr(p.data)

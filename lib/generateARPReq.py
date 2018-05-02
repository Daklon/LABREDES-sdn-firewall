from ryu.ofproto import ether
from ryu.lib.packet import ethernet, arp, packet

def genArpMessage(dstMac, dstIp, srcMac, srcIp, operation):

    if operation == 1:
        arpDstMac = '00:00:00:00:00:00'
    else:
        arpDstMac = dstMac

    e = ethernet.ethernet( dst = dstMac, src = srcMac, ethertype = ether.ETH_TYPE_ARP)

    a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=operation,
                src_mac = srcMac, src_ip = srcIp,
                dst_mac = arpDstMac, dst_ip = dstIp)
    msg = packet.Packet()
    msg.add_protocol(e)
    msg.add_protocol(a)
    msg.serialize()
    return msg

def genArpRequest(srcMac, srcIp, dstIp):

    p = genArpMessage('ff:ff:ff:ff:ff:ff', dstIp, srcMac, srcIp,0)
    print repr(p.data)

def genArpResponse(dstMac, dstIp, srcMac, srcIp):

    p = genArpMessage(dstMac, dstIp, srcMac, srcIp, 2)
    print repr(p.data)

def processArpRequest(p, srcMac, srcIp):

    a = get_protocol(arp)
    if a.dst_ip == ownIp:
        msg = genArpResponse(a.src_mac, a.src_ip, srcMac, srcIp)
        #save the ip-mac in the table


genArpRequest('00:00:00:00:00:01', '192.168.0.1', '192.168.0.2')  
genArpResponse('00:00:00:00:00:02', '192.68.0.2', '00:00:00:00:00:01', '192.168.0.1')

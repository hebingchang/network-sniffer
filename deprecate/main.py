import pcap
import network_sniffer
import consts

sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))

# consts.updateConsts()

for ts, pkt in sniffer:
    # decoded = decodePacket(sniffer, pkt)
    # print('%d\tSRC %-16s\tDST %-16s' % (ts, decoded['sourceIp'], decoded['destIp']))
    packet = network_sniffer.Packet(sniffer, pkt)
    # print([packet.ethHeader, packet.ipHeader])
    print(packet.parse())

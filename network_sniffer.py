import dpkt, utils
from dpkt.compat import compat_ord
import consts, pcap
from bitstring import BitArray
import ipaddress
from netaddr import *

class ipFlag:
    def __init__(self, flag):
        self.reversed = bool(flag[0] // 128)
        self.fragment = bool((flag[0] // 64) % 2)
        self.more_fragment = bool((flag[0] // 32) % 2)
        self.fragment_offset = (flag[0] - self.reversed * 128 - self.fragment * 64 - self.more_fragment * 32) * 256 + flag[1]

    def list(self):
        return {
            'reversed': self.reversed,
            'fragment': self.fragment,
            'more_fragment': self.more_fragment,
            'fragment_offset': self.fragment_offset
        }

class ethHeader:
    def __init__(self, buf):
        self.destMac = utils.mac_addr(buf[0:6])
        self.sourceMac = utils.mac_addr(buf[6:12])
        self.type = consts.eth_types[''.join('%02x' % compat_ord(b) for b in buf[12:14]).upper()]
        self.type_code = ''.join('%02x' % compat_ord(b) for b in buf[12:14]).upper()

class ipv4Header:
    def doChecksum(self, ipHeader, checksum):
        sum = 0
        weight = 256
        for index, byte in enumerate(ipHeader):
            if index != 10 and index != 11:
                sum += byte * weight
                weight = {256: 1, 1: 256}[weight]

        sum = (sum).to_bytes(3, 'big')
        return checksum[0] == 255 - sum[1] and checksum[1] == 255 - sum[0] - sum[2]

    def __init__(self, buf):
        bits = BitArray(buf)
        self.version = bits[0:4].int
        self.header_length = bits[4:8].int * 4           # bytes
        self.source_ip = str(ipaddress.IPv4Address(bits[96:96 + 32].bytes))
        self.dest_ip = str(ipaddress.IPv4Address(bits[96 + 32:96 + 64].bytes))
        self.differentiated_services = bits[8:16].hex
        self.total_length = bits[16:32].int    # bit
        self.identification = bits[32:48].hex
        self.flags = ipFlag([buf[6], buf[7]]).list()
        self.time_to_live = bits[64:72].int
        self.protocol = consts.protocol_types[str(bits[72:80].int)]
        self.checksum = self.doChecksum(buf[0:(buf[0] % 16) * 4], buf[10:12])

class arpBody:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.hardware_type_code = bits[0:16].int
        self.hardware_type = consts.arp_hardware_types[str(bits[0:16].int)]
        self.protocol_type_code = bits[16:32].hex
        self.protocol_type = consts.eth_types[str(bits[16:32].hex)]
        self.hardware_size = bits[32:40]
        self.protocol_size = bits[40:48]
        self.operation_code = bits[48:64].int
        mac = EUI(bits[64:112].hex)
        mac.dialect = mac_unix_expanded
        self.sender_mac_address = str(mac)
        self.sender_ip_address = str(ipaddress.IPv4Address(bits[112:144].bytes))
        mac = EUI(bits[144:192].hex)
        mac.dialect = mac_unix_expanded
        self.target_mac_address = str(mac)
        self.sender_ip_address = str(ipaddress.IPv4Address(bits[192:224].bytes))


class ipv6Header:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.header_length = 40
        self._class = bits[4:12]
        self.float_label = bits[12:32]
        self.payload_length = bits[32:48]
        self.next_header = consts.protocol_types[str(bits[48:56].int)]
        self.protocol = consts.protocol_types[str(bits[48:56].int)]

        self.hop_limit = bits[56:64]
        self.source_ip = str(ipaddress.IPv6Address(bits[64:64 + 128].bytes))
        self.dest_ip = str(ipaddress.IPv6Address(bits[64 + 128:64 + 256].bytes))

class Packet:
    def __init__(self, sniffer, pkt, id):
        self.id = id
        self.sniffer = sniffer
        self.pkt = pkt
        self.length = BitArray(pkt).length
        self.__ethHeader = pkt[0:sniffer.dloff]
        self.__ipData = pkt[sniffer.dloff:]

        self.ethHeader = ethHeader(self.__ethHeader)

        if self.ethHeader.type_code in ['0800', '86DD']:            # IPv4 / IPv6
            self.ipVersion = self.__ipData[0] // 16
            if self.ipVersion == 4:
                self.ipHeader = ipv4Header(self.__ipData)
            elif self.ipVersion == 6:
                self.ipHeader = ipv6Header(self.__ipData)

            self.source, self.destination, self.protocol = self.ipHeader.source_ip, self.ipHeader.dest_ip, self.ipHeader.protocol
        elif self.ethHeader.type_code == '0806':                    # ARP
            self.source, self.destination = self.ethHeader.sourceMac, self.ethHeader.destMac
            self.protocol = 'ARP'
            self.arpBody = arpBody(self.__ipData)
    
    def parse(self):
        eth = dpkt.ethernet.Ethernet(self.pkt)
        # print('Ethernet Frame: ', utils.mac_addr(eth.src), utils.mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet frame contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            return ""
        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        # return 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #        (utils.inet_to_str(ip.src), utils.inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,
        #         fragment_offset)
        return {
            'source': utils.inet_to_str(ip.src),
            'destination': utils.inet_to_str(ip.dst),
            'length': ip.len
        }

    def __str__(self):
        hex_string = ""
        for dig in self.pkt:
            hex_string += '{:02x} '.format(dig)
        return hex_string
'''
sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))

for ts, pkt in sniffer:
    packet = Packet(sniffer, pkt, 1)
'''
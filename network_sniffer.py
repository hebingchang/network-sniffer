import dpkt, utils
from dpkt.compat import compat_ord
import consts, pcap
from bitstring import BitArray
import ipaddress
from netaddr import *

class ipFlag:
    def __init__(self, flag):
        self.raw = '0x' + flag.hex
        self.reserved = flag[0]
        self.fragment = flag[1]
        self.more_fragment = flag[2]
        self.fragment_offset = flag[3:16].uint
        self.fragment_offset_bin = '%s %s %s %s' % (int(flag[3]), ''.join(flag[4:8].bin), ''.join(flag[8:12].bin), ''.join(flag[12:16].bin))

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
        self.version = bits[0:4].uint
        self.header_length = bits[4:8].uint * 4           # bytes
        self.source_ip = str(ipaddress.IPv4Address(bits[96:96 + 32].bytes))
        self.dest_ip = str(ipaddress.IPv4Address(bits[96 + 32:96 + 64].bytes))
        self.differentiated_services = bits[8:16].hex
        self.total_length = bits[16:32].uint    # bit
        self.identification = bits[32:48].hex
        self.identification_int = bits[32:48].uint
        self.flags = ipFlag(bits[48:64])
        self.time_to_live = bits[64:72].uint
        self.protocol = consts.protocol_types[str(bits[72:80].uint)]
        self.protocol_code = bits[72:80].uint
        self.origin_checksum = bits[80:96].hex
        self.checksum = self.doChecksum(buf[0:(buf[0] % 16) * 4], buf[10:12])

class arpBody:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.hardware_type_code = bits[0:16].uint
        self.hardware_type = consts.arp_hardware_types[str(bits[0:16].uint)]
        self.protocol_type_code = bits[16:32].hex
        self.protocol_type = consts.eth_types[str(bits[16:32].hex)]
        self.hardware_size = bits[32:40].uint
        self.protocol_size = bits[40:48].uint
        self.operation = consts.arp_operation_codes[str(bits[48:64].uint)]
        self.operation_code = bits[48:64].uint
        mac = EUI(bits[64:112].hex)
        mac.dialect = mac_unix_expanded
        self.sender_mac_address = str(mac)
        self.sender_ip_address = str(ipaddress.IPv4Address(bits[112:144].bytes))
        mac = EUI(bits[144:192].hex)
        mac.dialect = mac_unix_expanded
        self.target_mac_address = str(mac)
        self.target_ip_address = str(ipaddress.IPv4Address(bits[192:224].bytes))


class ipv6Header:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.header_length = 40
        self.version = bits[0:4].uint
        self._class = bits[4:12]
        self.float_label = bits[12:32]
        self.payload_length = bits[32:48]
        self.next_header = consts.protocol_types[str(bits[48:56].uint)]
        self.protocol = consts.protocol_types[str(bits[48:56].uint)]

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
        data = [
            {
                'label': '以太网帧头部 / Ethernet Headers',
                'value': '',
                'bold': True,
                'children': [
                    {
                        'label': '目的端 MAC 地址',
                        'value': self.ethHeader.destMac
                    },
                    {
                        'label': '发送端 MAC 地址',
                        'value': self.ethHeader.sourceMac
                    },
                    {
                        'label': '帧类型',
                        'value': '%s (0x%s)' % (self.ethHeader.type, self.ethHeader.type_code)
                    }
                ]
            }
        ]

        if self.protocol == 'ARP':
            data.append({
                'label': 'ARP 消息 / Address Resolution Protocol',
                'value': '',
                'bold': True,
                'children': [
                    {
                        'label': '硬件类型',
                        'value': '%s (%s)' % (
                        self.arpBody.hardware_type, self.arpBody.hardware_type_code)
                    },
                    {
                        'label': '协议类型',
                        'value': '%s (0x%s)' % (
                        self.arpBody.protocol_type, self.arpBody.protocol_type_code)
                    },
                    {
                        'label': '硬件地址长度',
                        'value': str(self.arpBody.hardware_size)
                    },
                    {
                        'label': '协议地址长度',
                        'value': str(self.arpBody.protocol_size)
                    },
                    {
                        'label': '操作码',
                        'value': '%s (%s)' % (self.arpBody.operation, self.arpBody.operation_code)
                    },
                    {
                        'label': '发送端 MAC 地址',
                        'value': self.arpBody.sender_mac_address
                    },
                    {
                        'label': '发送端 IP 地址',
                        'value': self.arpBody.sender_ip_address
                    },
                    {
                        'label': '目的端 MAC 地址',
                        'value': self.arpBody.target_mac_address
                    },
                    {
                        'label': '目的端 IP 地址',
                        'value': self.arpBody.target_ip_address
                    }
                ]
            })
        else:

            if self.ipHeader.version == 4:
                data.append({
                    'label': 'IPv4 头部 / IPv4 Header',
                    'value': '',
                    'bold': True,
                    'children': [
                        {
                            'label': '协议版本',
                            'value':  self.ipHeader.version
                        },
                        {
                            'label': '头部长度',
                            'value': str(self.ipHeader.header_length) + ' Bytes'
                        },
                        {
                            'label': '服务类型',
                            'value': '0x%s' % (self.ipHeader.differentiated_services)
                        },
                        {
                            'label': '来源 IP',
                            'value': self.ipHeader.source_ip
                        },
                        {
                            'label': '目标 IP',
                            'value': self.ipHeader.dest_ip
                        },
                        {
                            'label': '总长度',
                            'value': self.ipHeader.total_length
                        },
                        {
                            'label': '标识',
                            'value': '0x%s (%s)' % (self.ipHeader.identification, self.ipHeader.identification_int)
                        },
                        {
                            'label': '标志',
                            'value': '%s' % (self.ipHeader.flags.raw),
                            'children': [
                                {
                                    'label': '保留位',
                                    'value': '%s | %s... .... .... ....' % (self.ipHeader.flags.reserved, int(self.ipHeader.flags.reserved))
                                },
                                {
                                    'label': 'Don\'t fragment' ,
                                    'value': '%s | .%s.. .... .... ....' % (self.ipHeader.flags.fragment, int(self.ipHeader.flags.fragment))
                                },
                                {
                                    'label': 'More fragments',
                                    'value': '%s | ..%s. .... .... ....' % (self.ipHeader.flags.more_fragment, int(self.ipHeader.flags.more_fragment))
                                },
                                {
                                    'label': '分段偏移',
                                    'value': '%s | ...%s' % (self.ipHeader.flags.fragment_offset, self.ipHeader.flags.fragment_offset_bin)
                                }
                            ]
                        },
                        {
                            'label': '生存期',
                            'value': self.ipHeader.time_to_live
                        },
                        {
                            'label': '协议',
                            'value': '%s (%s)' % (self.ipHeader.protocol, self.ipHeader.protocol_code)
                        },
                        {
                            'label': '校验和',
                            'value': '0x%s (%s)' % (self.ipHeader.origin_checksum, '校验' + {True: '通过', False: '失败'}[self.ipHeader.checksum])
                        }
                    ]
                })

        return data

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
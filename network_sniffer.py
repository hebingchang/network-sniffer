import dpkt, utils
from dpkt.compat import compat_ord
import consts, pcap
from bitstring import BitArray
import ipaddress
from netaddr import *

class Sniffer:
    def __init__(self, sniffer):
        self.ip_packets = dict()
        self.ip_ids = dict()           # 处理 IP 分片的情况
        self.count = 0
        self.sniffer = sniffer

    def packetArrive(self, pkt):
        self.count += 1
        packet = Packet(self.sniffer, pkt, self.count, self.ip_packets, self.ip_ids)
        if packet.ethHeader.type_code == '0800':      # 处理 IP 分片
            self.ip_packets[self.count] = packet

            if packet.ipHeader.identification_int in self.ip_ids:
                self.ip_ids[packet.ipHeader.identification_int].append(packet.id)
            else:
                self.ip_ids[packet.ipHeader.identification_int] = [packet.id]

        return packet



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
    def __init__(self, buf):
        bits = BitArray(buf)
        self.version = bits[0:4].uint
        self.header_length = bits[4:8].uint * 4           # bytes
        self.source_ip = str(ipaddress.IPv4Address(bits[96:96 + 32].bytes))
        self.dest_ip = str(ipaddress.IPv4Address(bits[96 + 32:96 + 64].bytes))
        self.ip_bits = bits[96:96 + 64]
        self.differentiated_services = bits[8:16].hex
        self.total_length = bits[16:32].uint    # bit
        self.identification = bits[32:48].hex
        self.identification_int = bits[32:48].uint
        self.flags = ipFlag(bits[48:64])
        self.time_to_live = bits[64:72].uint
        self.protocol = consts.protocol_types[str(bits[72:80].uint)]
        self.protocol_code = bits[72:80].uint
        self.origin_checksum = bits[80:96].hex
        self.header_raw = bits[0: self.header_length * 8]

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
        self._class = bits[4:12].hex
        self.float_label = bits[12:32].hex
        self.payload_length = bits[32:48].uint
        self.next_header = consts.protocol_types[str(bits[48:56].uint)]
        self.protocol = consts.protocol_types[str(bits[48:56].uint)]
        self.next_header_code = bits[48:56].uint

        self.hop_limit = bits[56:64].uint
        self.source_ip = str(ipaddress.IPv6Address(bits[64:64 + 128].bytes))
        self.dest_ip = str(ipaddress.IPv6Address(bits[64 + 128:64 + 256].bytes))
        self.ip_bits = bits[64:64 + 256]

        self.options = []
        next_header = self.next_header_code
        offset = 320
        while next_header in [0, 60, 43, 44, 51, 50, 60, 135, 59]:
            self.protocol = consts.protocol_types[str(bits[offset:offset+8].uint)]
            self.options.append({
                'code': next_header,
                'next_header': bits[offset:offset+8].uint,
                'value': bits[offset:offset+64].hex
            })
            next_header = bits[offset:offset+8].uint
            offset += 64

class icmpHeader:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.type = bits[0:8].uint
        self.type_name = consts.icmp_types[str(bits[0:8].uint)]
        self.code = bits[8:16].uint
        self.checksum = bits[16:32].hex

class ipBody:
    def __init__(self, buf, protocol, ip_bits):
        if protocol == 'TCP':
            self.tcpHeader = tcpHeader(buf)
            self.parameters = buf, ip_bits
        elif protocol == 'UDP':
            self.udpHeader = udpHeader(buf)
            self.parameters = buf, ip_bits
        elif 'ICMP' in protocol:
            self.icmpHeader = icmpHeader(buf)
            self.parameters = buf

class tcpFlag:
    def __init__(self, buf):
        self.reserved = buf[0:3]
        self.nonce = buf[3]
        self.cwr = buf[4]
        self.ecn_echo = buf[5]
        self.urgent = buf[6]
        self.acknowledgement = buf[7]
        self.push = buf[8]
        self.reset = buf[9]
        self.syn = buf[10]
        self.fin = buf[11]

class tcpOptions:
    def __init__(self, buf):
        self.options = []
        offset = 0
        while buf[offset:offset+8].uint != 0:
            option = {'kind': buf[offset:offset+8].uint}

class tcpHeader:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.source_port = bits[0:16].uint
        self.destination_port = bits[16:32].uint
        self.sequence_number = bits[32:64].uint
        self.acknowledge_number = bits[64:96].uint
        self.header_length = bits[96:100].uint * 4           # bytes
        self.flags = tcpFlag(bits[100:112])
        self.flags_raw = bits[100:112].hex
        self.window_size = bits[112:128].uint
        self.checksum = bits[128:144].hex
        self.urgent_pointer = bits[144:160].uint
        # self.options = tcpOptions(bits[160:self.header_length*8])

class udpHeader:
    def __init__(self, buf):
        bits = BitArray(buf)
        self.source_port = bits[0:16].uint
        self.destination_port = bits[16:32].uint
        self.length = bits[32:48].uint
        self.checksum = bits[48:64].hex

class verifyChecksum:
    def doChecksum(self, bits, pseudobits, protocol):
        if pseudobits == []:    # IP / ICMP / IGMP
            checksum = 0
            if len(bits) % 16 != 0:
                bits.append('0x00')
            for i in range(0, len(bits), 16):
                checksum += bits[i: i + 16].uint
        else:                   # TCP UDP
            checksum = int(len(bits) / 8)
            if len(bits) % 16 != 0:
                bits.append('0x00')
            for i in range(0, len(bits), 16):
                checksum += bits[i: i + 16].uint
            while pseudobits.uint != 0:
                checksum += pseudobits[-16:].uint
                pseudobits = pseudobits >> 16
            if protocol == 'TCP':
                checksum += 6  # 传输层协议号
            elif protocol == 'UDP':
                checksum += 17

        if checksum > 65535:  # 0xffff
            sumArray = BitArray(hex(checksum))
            checksum = sumArray.uint - (sumArray >> 16).uint * 65535
        return checksum == 65535

    def __init__(self, buf, pseudobits, protocol):
        bits = BitArray(buf)
        self.verifyChecksum = self.doChecksum(bits, pseudobits, protocol)

class Packet:
    def __init__(self, sniffer, pkt, id, ip_packets, ip_ids):
        self.id = id
        self.sniffer = sniffer
        self.pkt = pkt
        self.length = BitArray(pkt).length
        self.__ethHeader = pkt[0:sniffer.dloff]
        self.__ipData = pkt[sniffer.dloff:]
        self.ip_packets = ip_packets
        self.ip_ids = ip_ids

        self.ethHeader = ethHeader(self.__ethHeader)

        if self.ethHeader.type_code in ['0800', '86DD']:            # IPv4 / IPv6
            self.ipVersion = self.__ipData[0] // 16
            if self.ipVersion == 4:
                self.ipHeader = ipv4Header(self.__ipData)
            elif self.ipVersion == 6:
                self.ipHeader = ipv6Header(self.__ipData)

            print('ipHeader parse complete.')

            self.source, self.destination, self.protocol = self.ipHeader.source_ip, self.ipHeader.dest_ip, self.ipHeader.protocol
            self.ipBodyRaw = self.__ipData[self.ipHeader.header_length:]

            if self.ethHeader.type_code == '0800':
                if not self.ipHeader.flags.more_fragment:
                    if self.ipHeader.identification_int != 0 and self.ipHeader.identification_int in self.ip_ids:
                        print('More fragment.')
                        for id in self.ip_ids[self.ipHeader.identification_int]:
                            self.ipBodyRaw += self.ip_packets[id].ipBodyRaw

            self.ipBody = ipBody(self.ipBodyRaw, self.ipHeader.protocol, self.ipHeader.ip_bits)
            print('ipBody parse complete.')

        elif self.ethHeader.type_code == '0806':                    # ARP
            self.source, self.destination = self.ethHeader.sourceMac, self.ethHeader.destMac
            self.protocol = 'ARP'
            self.arpBody = arpBody(self.__ipData)

        else:
            self.source = None
    
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
                self.ipHeader.verifyChecksum = verifyChecksum(self.ipHeader.header_raw, [], '').verifyChecksum
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
                            'value': '0x%s (%s)' % (self.ipHeader.origin_checksum, '校验' + {True: '通过', False: '失败'}[self.ipHeader.verifyChecksum])
                        }
                    ]
                })

            else:
                ipv6_header = {
                    'label': 'IPv6 头部 / IPv6 Header',
                    'value': '',
                    'bold': True,
                    'children': [
                        {
                            'label': '协议版本',
                            'value': self.ipHeader.version
                        },
                        {
                            'label': '通信分类',
                            'value': '0x%s' % (self.ipHeader._class)
                        },
                        {
                            'label': '流标签',
                            'value': '0x%s' % (self.ipHeader.float_label)
                        },
                        {
                            'label': '有效载荷长度',
                            'value': self.ipHeader.payload_length
                        },
                        {
                            'label': '下一头部类型',
                            'value': '%s (%s)' % (self.ipHeader.next_header, self.ipHeader.next_header_code)
                        },
                        {
                            'label': '跳数限制',
                            'value': self.ipHeader.hop_limit
                        },
                        {
                            'label': '源 IP',
                            'value': self.ipHeader.source_ip
                        },
                        {
                            'label': '目的 IP',
                            'value': self.ipHeader.dest_ip
                        }
                    ]
                }

                for option in self.ipHeader.options:
                    ipv6_header['children'].append(
                        {
                            'label': consts.protocol_types[str(option['code'])],
                            'value': '0x' + option['value'],
                            'children': [{
                                'label': '下一头部类型',
                                'value': '%s (%s)' % (consts.protocol_types[str(option['next_header'])], option['next_header'])
                            }]
                        }
                    )

                data.append(ipv6_header)

            if self.ipHeader.version == 4 and self.ipHeader.flags.more_fragment == True:
                print('Waiting for more fragments.')
                ids = self.ip_ids[self.ipHeader.identification_int]
                slicing = {
                    'label': 'IP 分片',
                    'value': '共 %s 个数据包' % len(ids),
                    'bold': True,
                    'children': []
                }
                for id in ids:
                    slicing['children'].append({
                        'label': '#%s' % id,
                        'value': '%s Bytes' % (self.ip_packets[id].length / 8)
                    })
                data.append(slicing)
            else:
                if self.ipHeader.protocol == 'TCP':
                    self.ipBody.tcpHeader.verifyChecksum = verifyChecksum(self.ipBody.parameters[0], self.ipBody.parameters[1], self.ipHeader.protocol).verifyChecksum
                    data.append({
                        'label': 'TCP 头部 / Transmission Control Protocol Header',
                        'value': '',
                        'bold': True,
                        'children': [
                            {
                                'label': '源端口',
                                'value': self.ipBody.tcpHeader.source_port
                            },
                            {
                                'label': '目的端口',
                                'value': self.ipBody.tcpHeader.destination_port
                            },
                            {
                                'label': '数据序号 (seq)',
                                'value': self.ipBody.tcpHeader.sequence_number
                            },
                            {
                                'label': '确认序号 (ack)',
                                'value': self.ipBody.tcpHeader.acknowledge_number
                            },
                            {
                                'label': '首部长度',
                                'value': self.ipBody.tcpHeader.header_length
                            },
                            {
                                'label': '标志位',
                                'value': '0x' + self.ipBody.tcpHeader.flags_raw,
                                'children': [
                                    {
                                        'label': 'Reserved',
                                        'value': '%s | %s. .... ....' % (
                                        self.ipBody.tcpHeader.flags.reserved.uint, self.ipBody.tcpHeader.flags.reserved.bin)
                                    },
                                    {
                                        'label': 'Nonce',
                                        'value': '%s | ...%d .... ....' % (
                                            self.ipBody.tcpHeader.flags.nonce, self.ipBody.tcpHeader.flags.nonce)
                                    },
                                    {
                                        'label': 'Congestion Window Reduced',
                                        'value': '%s | .... %d... ....' % (
                                            self.ipBody.tcpHeader.flags.cwr, self.ipBody.tcpHeader.flags.cwr)
                                    },
                                    {
                                        'label': 'ECN-Echo',
                                        'value': '%s | .... .%d.. ....' % (
                                            self.ipBody.tcpHeader.flags.ecn_echo,
                                            self.ipBody.tcpHeader.flags.ecn_echo)
                                    },
                                    {
                                        'label': 'Urgent',
                                        'value': '%s | .... ..%d. ....' % (
                                            self.ipBody.tcpHeader.flags.urgent, self.ipBody.tcpHeader.flags.urgent)
                                    },
                                    {
                                        'label': 'Acknowledgment',
                                        'value': '%s | .... ...%d ....' % (
                                            self.ipBody.tcpHeader.flags.acknowledgement,
                                            self.ipBody.tcpHeader.flags.acknowledgement)
                                    },
                                    {
                                        'label': 'Push',
                                        'value': '%s | .... .... %d...' % (
                                            self.ipBody.tcpHeader.flags.push, self.ipBody.tcpHeader.flags.push)
                                    },
                                    {
                                        'label': 'Reset',
                                        'value': '%s | .... .... .%d..' % (
                                            self.ipBody.tcpHeader.flags.reset, self.ipBody.tcpHeader.flags.reset)
                                    },
                                    {
                                        'label': 'Syn',
                                        'value': '%s | .... .... ..%d.' % (
                                            self.ipBody.tcpHeader.flags.syn, self.ipBody.tcpHeader.flags.syn)
                                    },
                                    {
                                        'label': 'Fin',
                                        'value': '%s | .... .... ...%d' % (
                                            self.ipBody.tcpHeader.flags.fin, self.ipBody.tcpHeader.flags.fin)
                                    }
                                ]
                            },
                            {
                                'label': '窗口大小',
                                'value': self.ipBody.tcpHeader.window_size
                            },
                            {
                                'label': '校验和',
                                'value': '0x%s (%s)' % (self.ipBody.tcpHeader.checksum, '校验' + {True: '通过', False: '失败'}[self.ipBody.tcpHeader.verifyChecksum])
                            }
                        ]
                    })

                elif self.ipHeader.protocol == 'UDP':
                    self.ipBody.udpHeader.verifyChecksum = verifyChecksum(self.ipBody.parameters[0], self.ipBody.parameters[1], self.ipHeader.protocol).verifyChecksum
                    data.append({
                        'label': 'UDP 头部 / User Datagram Protocol Header',
                        'value': '',
                        'bold': True,
                        'children': [
                            {
                                'label': '源端口',
                                'value': self.ipBody.udpHeader.source_port
                            },
                            {
                                'label': '目的端口',
                                'value': self.ipBody.udpHeader.destination_port
                            },
                            {
                                'label': '长度',
                                'value': self.ipBody.udpHeader.length
                            },
                            {
                                'label': '校验和',
                                'value': '0x%s (%s)' % (self.ipBody.udpHeader.checksum, '校验' + {True: '通过', False: '失败'}[self.ipBody.udpHeader.verifyChecksum])
                            }
                        ]
                    })

                elif 'ICMP' in self.ipHeader.protocol:
                    self.ipBody.icmpHeader.verifyChecksum = verifyChecksum(self.ipBody.parameters, [], self.ipHeader.protocol).verifyChecksum
                    data.append({
                        'label': 'ICMP 头部 / Internet Control Message Protocol Headers',
                        'value': '',
                        'bold': True,
                        'children': [
                            {
                                'label': '类型',
                                'value': '%s (%s)' % (self.ipBody.icmpHeader.type, self.ipBody.icmpHeader.type_name)
                            },
                            {
                                'label': '代码',
                                'value': self.ipBody.icmpHeader.code
                            },
                            {
                                'label': '校验和',
                                'value': '0x%s (%s)' % (self.ipBody.icmpHeader.checksum, '校验' + {True: '通过', False: '失败'}[self.ipBody.icmpHeader.verifyChecksum])
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
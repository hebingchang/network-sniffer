import requests
import os
import csv
from bitstring import BitArray

def updateConsts():
    r = requests.get('https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv')    # 以太类型
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/ieee-802-numbers.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv')    # 协议号
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/protocol-numbers.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/arp-parameters/arp-parameters-1.csv')  # ARP 操作码
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/arp-parameters-1.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/arp-parameters/arp-parameters-2.csv')  # ARP 硬件类型
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/arp-parameters-2.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/tcp-parameters/tcp-parameters-1.csv')  # TCP 头部选项
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/tcp-parameters-1.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/tcp-parameters/tcp-parameters-2.csv')  # TCP 头部选项 14 Alternative Checksum Number
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/tcp-parameters-2.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/icmp-parameters/icmp-parameters-types.csv')  # ICMP 类型
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/icmp-parameters-types.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers-1.csv')  # IGMPv2 类型
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/igmp-type-numbers-1.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get('https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv')  # DNS 类型
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/dns-parameters-4.csv', 'wb')
    f.write(r.content)
    f.close()

    r = requests.get(
        'https://www.iana.org/assignments/dns-parameters/dns-parameters-2.csv')  # DNS Classes
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/dns-parameters-2.csv', 'wb')
    f.write(r.content)
    f.close()

eth_types = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/ieee-802-numbers.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[1].split('-')
        if len(key) == 1:
            eth_types[row[1]] = row[4]
        else:
            for idx in range(BitArray('0x' + key[0]).uint, BitArray('0x' + key[1]).uint + 1):
                eth_types[str(BitArray('uint:16=' + str(idx)).hex).upper()] = row[4]

protocol_types = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/protocol-numbers.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[0].split('-')
        if len(key) == 1:
            protocol_types[row[0]] = row[1]
        else:
            for idx in range(int(key[0]), int(key[1]) + 1):
                protocol_types[str(idx)] = row[1]

arp_operation_codes = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/arp-parameters-1.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        arp_operation_codes[row[0]] = row[1]

arp_hardware_types = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/arp-parameters-2.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        arp_hardware_types[row[0]] = row[1]


tcp_options = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/tcp-parameters-1.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[0].split('-')
        if row[0] == '2':
            params = [
                {
                    'name': 'MSS Value',
                    'length': 16   # 16 bits
                }
            ]
        elif row[0] == '3':
            params = [
                {
                    'name': 'Shift count',
                    'length': 8   # 8 bits
                }
            ]
        elif row[0] == '5':
            params = [
                {
                    'name': 'left edge',
                    'length': 32
                },
                {
                    'name': 'right edge',
                    'length': 32
                }
            ]
        elif row[0] == '8':
            params = [
                {
                    'name': 'Timestamp value',
                    'length': 32
                },
                {
                    'name': 'Timestamp echo reply',
                    'length': 32
                }
            ]
        elif row[0] == '10':
            params = [
                {
                    'name': 'Start flag',
                    'length': 1
                },
                {
                    'name: ': 'End flag',
                    'length': 1
                },
                {
                    'name': 'Filter',
                    'length': 6
                }
            ]
        elif row[0] == '11' or row[0] == '12' or row[0] == '13':
            params = [
                {
                    'name': 'Connection Count',
                    'length': 24
                }
            ]
        elif row[0] == '14':
            params = [
                {
                    'name': 'chksum',
                    'length': 8
                }
            ]
        elif row[0] == '19':
            params = [
                {
                    'name': 'MD5 digest',
                    'length': 16 * 8
                }
            ]
        elif row[0] == '27':
            params = [
                {
                    'name': 'Resv.',
                    'length': 4
                },
                {
                    'name': 'Rate Request',
                    'length': 4
                },
                {
                    'name': 'TTL Diff',
                    'length': 8
                },
                {
                    'name': 'QS Nonce',
                    'length': 30
                },
                {
                    'name': 'R',
                    'length': 2
                }
            ]
        elif row[0] == '28':
            params = [
                {
                    'name': 'Granularity',
                    'length': 1
                },
                {
                    'name': 'User Timeout',
                    'length': 15
                }
            ]
        elif row[0] == '29':
            params = [
                {
                    'name': 'Key ID',
                    'length': 8
                },
                {
                    'name': 'RNextKeyID',
                    'length': 8
                },
                {
                    'name': 'MAC',
                    'variable': 1
                }
            ]
        else:
            params = []

        if params:
            tcp_options[int(row[0])] = {
                'length': 2,
                'meaning': row[2],
                'params': params
            }
        else:
            key = row[0].split('-')
            if len(key) == 1:
                tcp_options[int(row[0])] = {
                    'length': int('0' + row[1].replace('-', '1').replace('N', '2').replace('variable', '2')),
                    'meaning': row[2]
                }
            else:
                for idx in range(int(key[0]), int(key[1]) + 1):
                    tcp_options[idx] = {
                        'length': int('0' + row[1].replace('-', '1').replace('N', '2').replace('variable', '2')),
                        'meaning': row[2]
                    }
        # if length > 1, 实际 length 由 option 位的 8 到 15 位确定, 实际 length > 2, (length - 2) * 8 读取为 'Value'

icmp_types = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/icmp-parameters-types.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[0].split('-')
        if len(key) == 1:
            icmp_types[row[0]] = row[1]
        else:
            for idx in range(int(key[0]), int(key[1]) + 1):
                icmp_types[str(idx)] = row[1]

igmp_types = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/igmp-type-numbers-1.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[0].split('-')
        if len(key) == 1:
            igmp_types[int(row[0], 16)] = row[1]
        else:
            for idx in range(int(key[0], 16), int(key[1], 16) + 1):
                igmp_types[idx] = row[1]

dns_classes = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/dns-parameters-2.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[0].split('-')
        if len(key) == 1:
            dns_classes[int(row[0])] = row[2]
        else:
            for idx in range(int(key[0]), int(key[1]) + 1):
                dns_classes[idx] = row[2]

dns_types = dict()
with open(os.path.dirname(os.path.abspath(__file__)) + '/ieee_standards/dns-parameters-4.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    next(csvreader)
    for row in csvreader:
        key = row[1].split('-')
        if len(key) == 1:
            dns_types[int(row[1])] = row[0]
        else:
            for idx in range(int(key[0]), int(key[1]) + 1):
                dns_types[idx] = row[0]

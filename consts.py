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
        if row[0] == 2:
            params = [
                {
                    'name': 'MSS Value',
                    'length': 16
                }
            ]
        elif row[0] == 3:
            params = [
                {
                    'name': 'Shift count',
                    'length': 16
                }
            ]
        elif row[0] == 8:
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
        else:
            params = [
                {
                    'name': 'Value',
                    'length': (int('0' + row[1].replace('-', '1').replace('N', '1').replace('variable', '1')) - 1) * 8
                }
            ]
        tcp_options[row[0]] = {
            'length': int('0' + row[1].replace('-', '1').replace('N', '1').replace('variable', '1')),
            'meaning': row[2],
            'params': params
        }
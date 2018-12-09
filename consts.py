import requests
import os
import csv

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
        eth_types[row[1]] = row[4]

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
        tcp_options[row[0]] = {
            'length': row[1],
            'meaning': row[2]
        }
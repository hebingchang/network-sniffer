from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import QQmlApplicationEngine
from PyQt5.QtCore import QObject, pyqtSlot, QThread, pyqtSignal

import pcap, sys, queue, json, os, netifaces, psutil
import network_sniffer
from anytree.importer import JsonImporter
from anytree import RenderTree
from prettytable import PrettyTable
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

importer = JsonImporter()

#somewhere accessible to both:
callback_queue = queue.Queue()
listening = False
filter = ''
packets = list()

class SnifferThread(QThread):
    signal = pyqtSignal('PyQt_PyObject')

    def __init__(self):
        QThread.__init__(self)
        self.packet_count = 0
        self.dev = ''

    # run method gets called when we start the thread
    def run(self):
        global listening, filter
        print("Started. " + self.dev)
        addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))

        sniffer = pcap.pcap(name=self.dev, promisc=True, immediate=True, timeout_ms=50)
        # sniffer.setfilter('src host 10.162.81.65')
        try:
            sniffer.setfilter(filter)
            bug_sniffer = network_sniffer.Sniffer(sniffer)

            for ts, pkt in sniffer:
                self.packet_count += 1
                packet = bug_sniffer.packetArrive(pkt)
                if packet.source == None:
                    print('Packet not supported.')
                else:
                    data = {
                        'id': packet.id,
                        'source': packet.source,
                        'destination': packet.destination,
                        'protocol': packet.protocol,
                        'length': packet.length
                    }
                    # print(data)
                    self.signal.emit((data, packet))

                if listening == False:
                    break
        except OSError as err:
            self.signal.emit((err, None))

class parseController(QObject):
    def __init__(self, *args, **kwags):
        QObject.__init__(self, *args, **kwags)

    @pyqtSlot(int, result=str)
    def onItemChange(self, index):
        data = packets[index].parse()
        return json.dumps(data)

    @pyqtSlot(str)
    def setFilter(self, spec_filter):
        global filter
        filter = spec_filter

    @pyqtSlot(int, str)
    def savePacket(self, index, path):
        if os.name == 'nt':
            path = path.replace('file://', '')[1:]
        else:
            path = path.replace('file://', '')
        f = open(path, 'w')
        t = PrettyTable(['字段', '值'])
        t.align = 'l'

        root = importer.import_(json.dumps({
            'label': '数据包',
            'value': '',
            'children': packets[index].parse()
        }))
        for pre, fill, node in RenderTree(root):
            t.add_row([pre + node.label, node.value])
        f.write(str(t))
        f.close()

    @pyqtSlot(int, str, result=str)
    def saveTCP(self, index, path):
        if os.name == 'nt':
            path = path.replace('file://', '')[1:]
        else:
            path = path.replace('file://', '')

        if (index + 1) in network_sniffer.getTcpBodies():
            f = open(path, 'wb')

            try:
                p = HttpParser()
                recved = len(network_sniffer.getTcpBodies()[index + 1]['data'])
                nparsed = p.execute(network_sniffer.getTcpBodies()[index + 1]['data'], recved)
                assert nparsed == recved
                f.write(p.recv_body())

                ret = '解析到 HTTP 报文，已保存 HTTP 数据。'
            except AssertionError:
                f.write(network_sniffer.getTcpBodies()[index + 1]['data'])

                ret = '未解析到 HTTP 报文，已保存 TCP 数据。'

            f.close()

            return ret

        else:
            return '数据包不是 TCP 分段的最后一段。'

    @pyqtSlot(str, result=str)
    def search(self, keyword):
        result = []
        for bid in network_sniffer.getTcpBodies():
            if keyword.encode('utf-8') in network_sniffer.getTcpBodies()[bid]['data']:
                result.append('#%s' % bid)

        return '找到%s个数据包. '% len(result) + ', '.join(result)


class snifferGui:
    def __init__(self, argv):
        app = QGuiApplication(argv)
        engine = QQmlApplicationEngine()
        context = engine.rootContext()
        context.setContextProperty('mainWindow', engine)  # the string can be anything
        engine.load('./qt-gui/sniffer.qml')

        parse = parseController()
        context.setContextProperty('parse', parse)

        if os.name == 'nt':
            self.devs_name = list(psutil.net_if_addrs().keys())
            self.devs = ['\\\\Device\\\\NPF_' + x for x in netifaces.interfaces()]
        else:
            self.devs_name = self.devs = pcap.findalldevs()

        self.root = engine.rootObjects()[0]
        self.root.setDevModel(self.devs_name)
        self.dev = self.devs[0]
        self.sniffer_status = False

        # self.root.appendPacketModel({'source': '10.162.31.142', 'destination': '151.101.74.49', 'length': 52, 'id': 1})

        self.packetModel = self.root.findChild(QObject, "packetModel")

        self.sniffer_thread = SnifferThread()  # This is the thread object
        # Connect the signal from the thread to the finished method
        self.sniffer_thread.signal.connect(self.addItem)

        self.btnStart = self.root.findChild(QObject, "btnStart")
        self.btnStart.clicked.connect(self.myFunction)  # works too

        self.comboDev = self.root.findChild(QObject, "comboDevice")
        self.comboDev.activated.connect(self.getDev)

        packets = list()

        engine.quit.connect(app.quit)
        sys.exit(app.exec_())

        # sys.exit(app.exec_())

    def myFunction(self):
        global listening, filter
        if (self.sniffer_status):
            self.sniffer_status = False
            self.root.stopSnifferAction()
            # self.sniffer_thread.terminate()
            listening = False
        else:
            self.sniffer_status = True
            listening = True
            packets = list()
            self.root.startSnifferAction()
            self.sniffer_thread.dev = self.dev
            self.sniffer_thread.start()  # Finally starts the thread

    def addItem(self, data):
        if data[1] == None:
            self.root.msgbox('错误', "OSError: {0}".format(data[0]))
            self.myFunction()
        else:
            packets.append(data[1])
            self.root.appendPacketModel(data[0])

    def getDev(self, index):
        self.dev = self.devs[index]


def startGui():
    gui = snifferGui(sys.argv)

startGui()



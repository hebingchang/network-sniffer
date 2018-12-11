from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import QQmlApplicationEngine
from PyQt5.QtCore import QObject, pyqtSlot, QThread, pyqtSignal

import pcap, sys
import network_sniffer
import queue
import json
import os
import netifaces, psutil
from anytree.importer import JsonImporter
from anytree import RenderTree
importer = JsonImporter()

#somewhere accessible to both:
callback_queue = queue.Queue()
listening = False
packets = list()

class SnifferThread(QThread):
    signal = pyqtSignal('PyQt_PyObject')

    def __init__(self):
        QThread.__init__(self)
        self.packet_count = 0
        self.dev = ''

    # run method gets called when we start the thread
    def run(self):
        global listening
        print("Started. " + self.dev)
        addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))

        sniffer = pcap.pcap(name=self.dev, promisc=True, immediate=True, timeout_ms=50)
        # sniffer.setfilter('src host 10.162.81.65')
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
                print(data)
                self.signal.emit((data, packet))

            if listening == False:
                break

class parseController(QObject):
    def __init__(self, *args, **kwags):
        QObject.__init__(self, *args, **kwags)

    @pyqtSlot(int, result=str)
    def onItemChange(self, index):
        data = packets[index].parse()
        return json.dumps(data)

    @pyqtSlot(int, str)
    def savePacket(self, index, path):
        f = open(path.replace('file://', ''), 'w')
        write = []
        root = importer.import_(json.dumps({
            'label': '数据包',
            'value': '',
            'children': packets[index].parse()
        }))
        for pre, fill, node in RenderTree(root):
            write.append("%s%s: %s\n" % (pre, node.label, node.value))
        f.writelines(write)
        f.close()

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

        # engine.quit.connect(app.quit)
        app.exec_()
        del app

        # sys.exit(app.exec_())

    def myFunction(self):
        global listening
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
        packets.append(data[1])
        self.root.appendPacketModel(data[0])

    def getDev(self, index):
        self.dev = self.devs[index]


def startGui():
    gui = snifferGui(sys.argv)

startGui()



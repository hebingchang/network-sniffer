import time

from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import QQmlApplicationEngine, QQmlProperty
from PyQt5.QtCore import QUrl, QObject, pyqtSlot, QRunnable, QThreadPool, QAbstractListModel, QThread, pyqtSignal

import pcap, sys
import network_sniffer
import queue

#somewhere accessible to both:
callback_queue = queue.Queue()

listening = False

class SnifferThread(QThread):
    signal = pyqtSignal('PyQt_PyObject')

    def __init__(self):
        QThread.__init__(self)
        self.packet_count = 0
        self.dev = ''

    # run method gets called when we start the thread
    def run(self):
        print("Started. " + self.dev)
        sniffer = pcap.pcap(name=self.dev, promisc=True, immediate=True, timeout_ms=50)
        addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))

        for ts, pkt in sniffer:
            self.packet_count += 1
            packet = network_sniffer.Packet(sniffer, pkt, self.packet_count)
            data = {
                'id': packet.id,
                'source': packet.source,
                'destination': packet.destination,
                'protocol': packet.protocol,
                'length': packet.length
            }
            print(data)
            self.signal.emit(data)

class snifferGui:
    def __init__(self, argv):
        app = QGuiApplication(argv)
        engine = QQmlApplicationEngine()
        context = engine.rootContext()
        context.setContextProperty('mainWindow', engine)  # the string can be anything

        engine.load('./qt-gui/sniffer.qml')
        self.root = engine.rootObjects()[0]
        self.root.setDevModel(pcap.findalldevs())
        self.root.initPieMenu()
        self.dev = pcap.findalldevs()[0]
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

        engine.quit.connect(app.quit)
        sys.exit(app.exec_())

    def myFunction(self):
        if (self.sniffer_status):
            self.sniffer_status = False
            self.root.stopSnifferAction()
            self.sniffer_thread.terminate()
        else:
            self.sniffer_status = True
            self.root.startSnifferAction()
            self.sniffer_thread.dev = self.dev  # Get the git URL
            self.sniffer_thread.start()  # Finally starts the thread

    def addItem(self, data):
        self.root.appendPacketModel(data)

    def getDev(self, index):
        self.dev = pcap.findalldevs()[index]


def startGui():
    gui = snifferGui(sys.argv)

startGui()



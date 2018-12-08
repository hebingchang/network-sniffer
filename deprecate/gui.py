import time

from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import QQmlApplicationEngine, QQmlProperty
from PyQt5.QtCore import QUrl, QObject, pyqtSlot, QRunnable, QThreadPool, QAbstractListModel, QThread, pyqtSignal

import pcap, sys
import network_sniffer
import _thread
import asyncio, quamash
from threading import Thread
import queue

#somewhere accessible to both:
callback_queue = queue.Queue()

listening = False

class snifferGui:
    def __init__(self, argv):
        app = QGuiApplication(argv)
        engine = QQmlApplicationEngine()
        context = engine.rootContext()
        context.setContextProperty('mainWindow', engine)  # the string can be anything

        engine.load('/Users/hebingchang/QtCreator/sniffer/sniffer.qml')
        self.root = engine.rootObjects()[0]
        self.root.setDevModel(pcap.findalldevs())
        self.dev = pcap.findalldevs()[0]
        self.sniffer_status = False

        # self.root.appendPacketModel({'source': '10.162.31.142', 'destination': '151.101.74.49', 'length': 52, 'id': 1})

        self.packetModel = self.root.findChild(QObject, "packetModel")

        btnStart = self.root.findChild(QObject, "btnStart")
        btnStart.clicked.connect(self.myFunction)  # works too

        self.comboDev = self.root.findChild(QObject, "comboDevice")
        self.comboDev.activated.connect(self.getDev)

        engine.quit.connect(app.quit)
        sys.exit(app.exec_())

    def from_dummy_thread(self, func_to_call_from_main_thread):
        callback_queue.put(func_to_call_from_main_thread)

    def from_main_thread_blocking(self):
        callback = callback_queue.get()  # blocks until an item is available
        callback()

    def from_main_thread_nonblocking(self):
        while True:
            try:
                callback = callback_queue.get(False)  # doesn't block
            except queue.Empty:  # raised when queue is empty
                break
            callback()

    def sniffer(self, appendPacketModel):
        print("Started. " + self.dev)
        self.packet_count = 0
        sniffer = pcap.pcap(name=self.dev, promisc=True, immediate=True, timeout_ms=50)
        addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))

        for ts, pkt in sniffer:
            if (self.sniffer_status == False):
                print("Stop.")
                break

            self.packet_count += 1
            packet = network_sniffer.Packet(sniffer, pkt)
            data = packet.parse()
            # data['id'] = self.packet_count

            appendPacketModel({'source': '10.162.31.142', 'destination': '151.101.74.49', 'length': 52, 'id': 1})

            print(data)

    def myFunction(self):
        if self.sniffer_status == False:
            self.sniffer_status = True
            self.sniffer_thread = Thread(target=self.sniffer, args=(self.root.appendPacketModel))
            self.sniffer_thread.start()
            self.sniffer_thread.join()
        else:
            self.sniffer_status = False

    def getDev(self, index):
        self.dev = pcap.findalldevs()[index]


def startGui():
    gui = snifferGui(sys.argv)

startGui()
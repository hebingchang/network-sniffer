from PyQt5.QtGui import QGuiApplication, QIcon
from PyQt5.QtQml import QQmlApplicationEngine
from PyQt5.QtCore import QObject, pyqtSlot, QThread, pyqtSignal, Qt

import pcap, sys, queue, json, os, netifaces, psutil
from core import network_sniffer
from anytree.importer import JsonImporter
from anytree import RenderTree
from prettytable import PrettyTable
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

importer = JsonImporter()

callback_queue = queue.Queue()
listening = False
filter = ''
packets = list()
os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"


# 由于抓包操作将会阻塞线程，必须新开一个线程专门负责抓包
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
        try:
            sniffer.setfilter(filter)

            # It's named after bug sniffer because it's full of bug! :(
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

# 与 GUI 界面的一些数据交互，在 qml 中体现为 parse.xxxx()
class parseController(QObject):
    def __init__(self, *args, **kwags):
        QObject.__init__(self, *args, **kwags)

    # 列表选中项目改变事件
    @pyqtSlot(int, result=str)
    def onItemChange(self, index):
        print(index, len(packets))
        data = packets[index].parse()
        return json.dumps(data)
    
    # 设置过滤器
    @pyqtSlot(str)
    def setFilter(self, spec_filter):
        global filter
        filter = spec_filter
    
    # 保存数据包
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
    
    # 保存 TCP 分段数据
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
    
    # 搜索数据包
    @pyqtSlot(str, result=str)
    def search(self, keyword):
        result = []
        for bid in network_sniffer.getTcpBodies():
            if keyword.encode('utf-8') in network_sniffer.getTcpBodies()[bid]['data']:
                result.append('#%s' % bid)

        return '找到%s个数据包. '% len(result) + ', '.join(result)

# 主窗体类
class snifferGui:
    def __init__(self, argv):
        self.app = QGuiApplication(argv)
        self.app.setWindowIcon(QIcon('qt-gui/images/icon.png'))
        self.app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    
    # 初始化一些必须的对象并运行窗体. 这一过程将会在 app.exec_() 被阻塞
    def load(self):
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

        self.packetModel = self.root.findChild(QObject, "packetModel")

        self.sniffer_thread = SnifferThread()  # This is the thread object
        # Connect the signal from the thread to the finished method
        self.sniffer_thread.signal.connect(self.addItem)

        self.btnStart = self.root.findChild(QObject, "rowLayout1").findChild(QObject, "btnStart")
        self.btnStart.clicked.connect(self.toggleSniffer)

        self.comboDev = self.root.findChild(QObject, "comboDevice")
        self.comboDev.activated.connect(self.getDev)

        engine.quit.connect(self.app.quit)

        return self.app.exec_()

    def toggleSniffer(self):
        global listening, filter, packets
        if (self.sniffer_status):
            self.sniffer_status = False
            self.root.stopSnifferAction()
            # self.sniffer_thread.terminate()
            listening = False
        else:
            self.sniffer_status = True
            listening = True
            self.root.clearList()
            packets = list()
            network_sniffer.init_tcp()
            self.root.startSnifferAction()
            self.sniffer_thread.dev = self.dev
            self.sniffer_thread.start()  # Finally starts the thread

    def addItem(self, data):
        if data[1] == None:
            self.root.msgbox('错误', "OSError: {0}".format(data[0]))
            self.toggleSniffer()
        else:
            packets.append(data[1])
            self.root.appendPacketModel(data[0])

    def getDev(self, index):
        self.dev = self.devs[index]


def startGui():
    gui = snifferGui(sys.argv)
    ret_code = gui.load()
    sys.exit(ret_code)

startGui()
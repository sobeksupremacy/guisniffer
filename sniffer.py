import sys
from mainwindow import *
from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import *


class MyWin(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        QtWidgets.QWidget.__init__(self, parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.pushButton.clicked.connect(beacon_sniff)
    
    
def packethandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
                    rssi = -(256-ord(pkt.notdecoded[-2: -1]))
                    myapp.ui.listWidget.addItem("MAC: %s SSID: %s RSSI: %s dBm" % (pkt.addr2, pkt.info, rssi))
    

def beacon_sniff():
    sniff(iface='mon0', prn=packethandler, count=300)


if __name__=="__main__":
    app = QtWidgets.QApplication(sys.argv)
    myapp = MyWin()
    myapp.show()
    sys.exit(app.exec_())
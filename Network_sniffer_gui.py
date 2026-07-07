import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QHBoxLayout
)
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Metasploit"
}

class SnifferThread(QThread):
    packet_signal = pyqtSignal(str, str, str, str, str)

    def process_packet(self, packet):
        if packet.haslayer(IP):
            time = datetime.now().strftime("%H:%M:%S")
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "Other"
            port = "N/A"

            if packet.haslayer(TCP):
                proto = "TCP"
                port = packet[TCP].dport

            elif packet.haslayer(UDP):
                proto = "UDP"
                port = packet[UDP].dport

            self.packet_signal.emit(
                time,
                src,
                dst,
                proto,
                str(port)
            )

    def run(self):
        sniff(prn=self.process_packet, store=False)

class SnifferGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Cyber Packet Sniffer")
        self.resize(900, 500)

        layout = QVBoxLayout()

        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start")
        self.clear_btn = QPushButton("Clear")

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.clear_btn)

        layout.addLayout(button_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(5)

        self.table.setHorizontalHeaderLabels([
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Port"
        ])

        layout.addWidget(self.table)

        self.alert = QLabel("Alerts: None")
        layout.addWidget(self.alert)

        self.setLayout(layout)

        self.thread = SnifferThread()

        self.start_btn.clicked.connect(self.start_capture)
        self.clear_btn.clicked.connect(self.clear_table)

        self.thread.packet_signal.connect(self.add_packet)

    def start_capture(self):
        self.thread.start()

    def clear_table(self):
        self.table.setRowCount(0)

    def add_packet(self, t, src, dst, proto, port):

        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row,0,QTableWidgetItem(t))
        self.table.setItem(row,1,QTableWidgetItem(src))
        self.table.setItem(row,2,QTableWidgetItem(dst))
        self.table.setItem(row,3,QTableWidgetItem(proto))
        self.table.setItem(row,4,QTableWidgetItem(port))

        try:
            p = int(port)

            if p in SUSPICIOUS_PORTS:
                self.alert.setText(
                    f"ALERT: {SUSPICIOUS_PORTS[p]} detected"
                )

        except:
            pass


app = QApplication(sys.argv)

window = SnifferGUI()
window.show()

sys.exit(app.exec()) 
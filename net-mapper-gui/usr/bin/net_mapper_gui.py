import sys
import socket
import json
import os
import nmap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QPushButton, QTableWidget, QTableWidgetItem, QLabel, QHBoxLayout, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QColor, QFont, QBrush

CACHE_FILE = "devices_cache.json"

GITHUB_PASTEL_DARK_STYLE = """
QMainWindow {
    background-color: #0d1117;
}
QLabel {
    color: #c9d1d9;
    font-size: 13px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
QPushButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: normal;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
    color: #58a6ff;
}
QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}
QTableWidget {
    background-color: #0d1117;
    alternate-background-color: #161b22;
    gridline-color: #30363d;
    border: 1px solid #30363d;
    border-radius: 6px;
    font-size: 13px;
    color: #c9d1d9;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #30363d;
    border-right: 1px solid #30363d;
    font-weight: normal;
}
"""

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def ip_sort_key(device):
    """Converte l'IP in una tupla di interi per un ordinamento numerico corretto (.2 prima di .10)"""
    try:
        return tuple(map(int, device["ip"].split('.')))
    except ValueError:
        return (999, 999, 999, 999)

def get_open_ports(nm, host):
    ports = []
    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for p in sorted(nm[host][proto].keys()):
                info = nm[host][proto][p]
                if info['state'] == 'open':
                    ports.append(f"{p}/{info['name']}")
    return ", ".join(ports) if ports else "-"

class NetworkScanWorker(QThread):
    scan_finished = pyqtSignal(list)

    def run(self):
        current_scan_devices = []
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')
            
            for host in nm.all_hosts():
                hostname = nm[host].hostname() if nm[host].hostname() else "Unknown"
                mac = "N/D"
                if 'mac' in nm[host]['addresses']:
                    mac = nm[host]['addresses']['mac']
                
                key = mac if mac != "N/D" else host
                
                current_scan_devices.append({
                    "key": key,
                    "ip": host,
                    "name": hostname,
                    "mac": mac,
                    "ports": "-"
                })

            live = [d["ip"] for d in current_scan_devices]
            if live:
                ps = nmap.PortScanner()
                ps.scan(hosts=' '.join(live), arguments='-F -T4 --open')
                for d in current_scan_devices:
                    d["ports"] = get_open_ports(ps, d["ip"])
        except Exception as e:
            print(f"Scan error: {e}")
            
        self.scan_finished.emit(current_scan_devices)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Local Network Scanner")
        self.resize(1040, 580)
        
        self.local_ip = get_local_ip()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # Status Label
        self.status_label = QLabel(f"Your Local IP: {self.local_ip} | Ready.")
        self.status_label.setFont(QFont("Segoe UI", 11))
        layout.addWidget(self.status_label)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP Address", "Hostname / Device Name", "MAC Address", "Open Ports"])
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        
        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 220)
        
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)
        
        # Scan Button
        self.scan_button = QPushButton("Start Network Scan")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # Footer Legend Layout
        legend_layout = QHBoxLayout()
        legend_layout.setSpacing(20)
        
        def create_legend_item(text, color_hex):
            lbl = QLabel(f"● {text}")
            lbl.setStyleSheet(f"color: {color_hex}; font-size: 12px;")
            return lbl

        legend_layout.addWidget(create_legend_item("Self", "#cba6f7"))
        legend_layout.addWidget(create_legend_item("Online", "#a6e3a1"))
        legend_layout.addWidget(create_legend_item("Offline", "#f38ba8"))
        legend_layout.addWidget(create_legend_item("New", "#89b4fa"))
        legend_layout.addStretch()

        layout.addLayout(legend_layout)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.status_label.setText("🔍 Scanning network in progress... Comparing cache...")
        self.table.setRowCount(0)
        
        self.worker = NetworkScanWorker()
        self.worker.scan_finished.connect(self.process_scan_results)
        self.worker.start()

    def process_scan_results(self, current_devices):
        previous_cache = {}
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    previous_cache = json.load(f)
            except Exception:
                previous_cache = {}

        current_cache = {}
        combined_display_list = []

        for dev in current_devices:
            key = dev["key"]
            is_new = key not in previous_cache
            
            dev_status = "new" if is_new else "online"
            
            current_cache[key] = {
                "ip": dev["ip"],
                "name": dev["name"],
                "mac": dev["mac"],
                "ports": dev.get("ports", "-"),
                "status": "online"
            }
            combined_display_list.append({**dev, "display_status": dev_status})

        for key, old_dev in previous_cache.items():
            if key not in current_cache:
                combined_display_list.append({
                    "key": key,
                    "ip": old_dev["ip"],
                    "name": old_dev["name"],
                    "mac": old_dev["mac"],
                    "ports": old_dev.get("ports", "-"),
                    "display_status": "offline"
                })
                current_cache[key] = {
                    "ip": old_dev["ip"],
                    "name": old_dev["name"],
                    "mac": old_dev["mac"],
                    "ports": old_dev.get("ports", "-"),
                    "status": "offline"
                }

        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(current_cache, f, indent=4)
        except Exception as e:
            print(f"Cache save error: {e}")

        # Ordina la lista combinata numericamente per IP prima di mostrarla
        combined_display_list.sort(key=ip_sort_key)

        self.populate_table(combined_display_list)

    def populate_table(self, devices):
        self.table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            is_me = (device["ip"] == self.local_ip)
            status = device["display_status"]
            
            dot = "●  "
            
            if is_me:
                color = QColor("#cba6f7")
            elif status == "offline":
                color = QColor("#f38ba8")
            elif status == "new":
                color = QColor("#89b4fa")
            else:
                color = QColor("#a6e3a1")

            ip_text = f"{dot}{device['ip']} (You)" if is_me else f"{dot}{device['ip']}"
            if status == "offline":
                ip_text += " [OFFLINE]"

            ip_item = QTableWidgetItem(ip_text)
            name_text = f"{device['name']} [This PC]" if is_me and device['name'] == "Unknown" else device["name"]
            name_item = QTableWidgetItem(name_text)
            mac_item = QTableWidgetItem(device["mac"])
            ports_item = QTableWidgetItem(device.get("ports", "-"))
            
            brush = QBrush(color)
            ip_item.setForeground(brush)
            name_item.setForeground(brush)
            mac_item.setForeground(brush)
            ports_item.setForeground(brush)

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, mac_item)
            self.table.setItem(row, 3, ports_item)
            
        self.status_label.setText(f"✨ Scan completed. Data saved to {CACHE_FILE}. Total: {len(devices)}")
        self.scan_button.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(GITHUB_PASTEL_DARK_STYLE)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

# Local Network Device Mapper

A functional, aesthetic GitHub Dark Pastel-themed network scanner for Linux, built with **Python**, **PyQt6**, and **Nmap**.

## Features

* **Network Discovery**: Scans your local network using Nmap to discover active hosts and devices.

* **Persistent Cache**: Automatically saves scan states to a local JSON file (`devices_cache.json`) to track device state changes (`Online`, `Offline`, `New`).

* **Intelligent IP Sorting**: Custom numerical sorting ensures IPs are ordered correctly (e.g., `.1`, `.2`, `.10` instead of alphabetical order).

* **GitHub Dark Pastel UI**: Clean, modern interface tailored for developers and sysadmins, featuring distinct status indicators:

  * **Self**: Purple

  * **Online**: Green

  * **Offline**: Red

  * **New**: Blue

* **Wide Hostname Column**: 320px default width for clear readability of device names and aliases.

## Requirements

* **Linux** (Debian/Ubuntu-based distributions recommended)

* **Python 3**

* **PyQt6**

* **Python-Nmap**

* **Nmap** (system package)

## Installation

### Method 1: Easy Installation via `.deb` (Recommended)

1. Download the latest `net-mapper-gui.deb` from the [Releases](https://github.com/JonaDev2026/Local-Network-Device-Mapper/releases/latest) page.

2. Install it using your terminal:

   ```
   sudo apt install ./net-mapper-gui.deb
   ```

3. Launch **Local Network Scanner** directly from your application menu or by running `net-mapper-gui` in the terminal.

### Method 2: Manual Execution from Source

1. Ensure dependencies are installed:

   ```
   sudo apt update
   sudo apt install nmap python3 python3-pyqt6 python3-nmap
   ```

2. Run the script:

   ```
   python3 net_mapper_gui.py
   ```

## License

Distributed under the MIT License. See `LICENSE` for more information.
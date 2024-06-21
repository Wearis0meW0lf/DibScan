# DibScan - Recon Tool

Welcome to **DibScan**, a versatile reconnaissance tool that automates network scanning and directory fuzzing using RustScan, Nmap, and FFUF.

## Prerequisites

Before running DibScan, ensure you have the following prerequisites installed and configured on your system:

1. **Docker**: Used to run the RustScan container.
2. **RustScan Docker Image**: Pull the latest RustScan Docker image.
3. **Python 3.6+**: Ensure you have Python installed and set as the default Python version.
4. **Python Libraries**: Required Python libraries listed in `requirements.txt`.

### Docker Installation

Install Docker if you haven't already:

- **For Debian-based systems (Ubuntu, etc.)**: `sudo apt update && sudo apt install -y docker.io`
- **For Red Hat-based systems (Fedora, CentOS, etc.)**: `sudo dnf install -y docker && sudo systemctl start docker && sudo systemctl enable docker`

### RustScan Docker Image

Pull the latest RustScan Docker image: `docker pull rustscan/rustscan:latest`

### Python and Libraries

Ensure Python 3.6+ is installed and set as the default Python version. Uses standard python libraries.

## Usage

To run DibScan: `sudo python3 dibscan.py`
DibScan is ran with Sudo Privs in order to edit the /ets/hosts file.

## Features

- Automated network scanning using RustScan and Nmap
- Directory fuzzing with FFUF
- Customizable scan options
- Output results in various formats

## Disclaimer

DibScan is intended for ethical use only. Always obtain proper authorization before scanning any networks or systems you do not own or have explicit permission to test.

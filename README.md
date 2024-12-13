# Port Scanner with Advanced Nmap Features

This repository contains a Python script that leverages **Nmap** to perform comprehensive network scanning, service detection, and vulnerability assessment. It uses advanced Nmap options to identify OS information, running services, and known vulnerabilities on a target host.

**Key Features:**
- **Port Scanning:** Checks open TCP ports on a given target.
- **Version Detection:** Identifies the versions of services running on open ports.
- **OS Detection:** Attempts to guess the operating system of the target.
- **Vulnerability Scripts:** Runs Nmap’s `--script=vuln` checks to identify known vulnerabilities.
- **XML Parsing:** Outputs Nmap results as XML, then parses and displays them in a structured manner.

## Prerequisites

- **Python 3.x**
- **Nmap Installed**:  
  - On Debian/Ubuntu: `sudo apt-get install nmap`  
  - On Fedora/CentOS: `sudo yum install nmap`  
  - On macOS (with Homebrew): `brew install nmap`  
- **Git (Optional)** if you want to clone the repository directly.

## Installation

1. **Clone the Repository (Optional):**
   ```bash
   git clone https://github.com/DipesThapa/PortScanner.git
   cd PortScanner

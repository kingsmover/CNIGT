# CNIGT v2.1.0 - Current Network Information Gathering Tool

**An automated network reconnaissance and vulnerability scanning tool with Metasploit integration.**
![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Stars](https://img.shields.io/github/stars/kingsmover/CNIGT)
![Version](https://img.shields.io/badge/version-2.1.0-orange.svg)
---

## ⚠️ LEGAL DISCLAIMER

**This tool is for authorized security testing and educational purposes ONLY.**

**YOU MUST HAVE EXPLICIT PERMISSION** to scan any network you do not own or administrate.

### Unauthorized network scanning is:
- **ILLEGAL** in most jurisdictions
- Violates computer fraud and abuse laws
- May result in **criminal charges, fines, or imprisonment**
- Could get you **banned** from networks/services

### Use CNIGT only on:
- Your own home/office networks
- Networks you have **written permission** to test
- Your own lab/virtual environments
- Educational sandboxes and CTF environments

**The developer assumes NO responsibility for misuse of this tool. Use ethically and legally.**

---

## 📖 Featured Article

**[Read the full story on Medium: Building CNIGT - From Discovery to Exploitation](https://kingsmover.medium.com/building-cnigt-an-automated-network-reconnaissance-tool-that-goes-from-discovery-to-exploitation-6606fc06a172)**

*Learn about the design decisions, technical challenges, and lessons learned while building this tool.*

## Features

### v2.1.0 New Features
- **Metasploit Integration** - Launch msfconsole directly from the tool
- **CVE Detection** - Automatically extracts and highlights CVE IDs from vulnerability scans
- **Colored Output** - Open ports highlighted in green for easy identification
- **Post-Scan Menu** - Interactive menu after scans with multiple options
- **Custom Port Ranges** - Specify exactly which ports to scan
- **Persistent Context** - Re-run scans with different options without restarting

### Core Features
- **Automatic Network Detection** - Detects IP, subnet mask, and CIDR automatically
- **Dual Discovery Methods** - Choose between arp-scan (fast) or ping (universal)
- **Thorough Mode** - Enhanced arp-scan with high retry for slow-responding devices
- **Rich Terminal UI** - Beautiful tables, colored output, and progress bars
- **Comprehensive Nmap Options** - 13+ scan options including vulnerability scanning
- **Host Information** - IP, MAC address, vendor, and hostname resolution
- **Session Persistence** - Maintains scan context for efficient workflow

---

## Prerequisites

### Required
- **Python 3.6+**
- **nmap** - Network scanning tool
- **ping** - Usually pre-installed
- **rich** - Python library for terminal formatting

### Recommended
- **arp-scan** - Fast host discovery (auto-installs if missing)
- **net-tools** - Provides ifconfig (auto-installs if missing)

### Optional
- **Metasploit Framework** - For exploitation (auto-installs if needed)

---

## Installation

### Quick Install (Debian/Ubuntu/Kali)

```bash
# One-liner installation
sudo apt update && sudo apt install -y python3 python3-pip nmap arp-scan net-tools && pip install rich

# Clone the repository
git clone https://github.com/kingsmover/CNIGT.git
cd CNIGT

# Make executable
chmod +x CNIGT.py

# Run the tool
sudo python3 CNIGT.py
```

### Manual Installation

#### Step 1: Install Python Dependencies
```bash
# Install pip if needed
sudo apt update
sudo apt install python3-pip -y

# Install required Python packages
pip install -r requirements.txt
# or
pip install rich
```

#### Step 2: Install System Tools
```bash
# Required tools
sudo apt install nmap -y

# Recommended tools
sudo apt install arp-scan net-tools -y
```

#### Step 3: Verify Installation
```bash
python3 --version  # Should be 3.6+
nmap --version
arp-scan --version  # Optional but recommended
pip show rich
```

---

## Usage

### Basic Usage
```bash
sudo python3 CNIGT.py
```

### Typical Workflow

1. **Network Detection**
   - Tool auto-detects your network interfaces
   - Select network or enter manually

2. **Choose Discovery Method**
   - Option 1: arp-scan (fast, shows MAC/Vendor)
   - Option 2: ping (slower, universal)

3. **Select Scan Mode** (if arp-scan)
   - Normal: Fast scan for most networks
   - Thorough: Catches slow-responding devices

4. **Host Discovery**
   - Tool scans and displays all online hosts
   - Shows IP, MAC, Vendor, and Hostname

5. **Configure Nmap Options**
   - Select from 13+ scan options
   - Custom port ranges
   - Vulnerability scanning

6. **Scan Target**
   - Select host from list or scan all
   - View colored output (green = open ports)
   - CVE IDs automatically highlighted

7. **Post-Scan Actions**
   - Re-scan with different options
   - Scan another host
   - Launch Metasploit if vulnerabilities found
   - Exit or continue scanning

---

## Nmap Options

| Option | Flag | Description |
|--------|------|-------------|
| 1 | `-sV` | Service Version Detection |
| 2 | `-O` | OS Detection (requires sudo) |
| 3 | `-p-` | Scan All 65535 Ports |
| 4 | `-p 1-1000` | Scan Ports 1-1000 |
| 5 | `-F` | Fast Scan (top 100 ports) |
| 6 | `-p custom` | Custom Port Range |
| 7 | `-sC` | Default NSE Scripts |
| 8 | `-A` | Aggressive Scan |
| 9 | `--open` | Show Only Open Ports |
| 10 | `-T4` | Aggressive Timing |
| 11 | `-v` | Verbose Output |
| 12 | `-Pn` | Skip Host Discovery |
| 13 | `--script vuln` | **Vulnerability Scan (CVE Detection)** |

---

## Features in Action

### Colored Output
```
✅ Found: 192.168.1.1 (aa:bb:cc:dd:ee:ff) - TP-Link
✅ Found: 192.168.1.100 (11:22:33:44:55:66) - Apple

22/tcp   open  ssh      [GREEN]
80/tcp   open  http     [GREEN]
443/tcp  open  https    [GREEN]
```

### CVE Detection
```
🚨 Found vulnerability: CVE-2021-44228  [RED]
🚨 Found vulnerability: CVE-2022-1234  [RED]

Found 2 CVE(s):
   • CVE-2021-44228
   • CVE-2022-1234
```

### Post-Scan Menu
```
WHAT WOULD YOU LIKE TO DO NEXT?

[1] Re-run host discovery (ping)
[2] Re-run host discovery (arp-scan)
[3] Scan last IP again with different options
[4] Scan a different IP from discovered hosts
[5] Scan a custom IP address
[6] Launch Metasploit (vulnerabilities found!)
[7] Exit tool
```

---

## Metasploit Integration

When vulnerabilities are found, CNIGT can launch Metasploit Framework:

1. **Legal Disclaimer** - Ensures responsible use
2. **Auto-Installation** - Installs Metasploit if not present
3. **CVE Information** - Shows discovered CVEs
4. **Search Tips** - Provides Metasploit commands
5. **Direct Launch** - Opens msfconsole with context

### Example Metasploit Workflow
```bash
# After vulnerability scan finds CVE-2021-44228
[6] Launch Metasploit

# In msfconsole:
msf6 > search CVE-2021-44228
msf6 > use exploit/multi/http/log4shell
msf6 > set RHOSTS 192.168.1.100
msf6 > exploit
```

---

## Platform Support

| OS | Support | Notes |
|----|---------|-------|
| Kali Linux | ✅ Full | Recommended platform |
| Ubuntu/Debian | ✅ Full | All features supported |
| CentOS/RHEL | ✅ Full | May need EPEL for arp-scan |
| Arch Linux | ✅ Full | All features supported |
| macOS | ⚠️ Partial | Limited arp-scan support |
| Windows (WSL) | ⚠️ Partial | Use WSL2 for best results |

---

## Troubleshooting

### Common Issues

**Issue: ModuleNotFoundError: No module named 'rich'**
```bash
pip install rich
# or
pip3 install rich
```

**Issue: arp-scan: command not found**
```bash
sudo apt install arp-scan
# The tool will also offer to auto-install
```

**Issue: Permission denied**
```bash
# run with sudo (Recommanded)
sudo python3 CNIGT.py
# or
sudo ./CNIGT.py # if executable
```

**Issue: No hosts found**
- Check if you're on the correct network
- Try thorough arp-scan mode
- Verify firewall isn't blocking ICMP/ARP
- Try ping discovery method

**Issue: Metasploit won't install**
```bash
# Manual installation for Kali
sudo apt update
sudo apt install metasploit-framework

# For other distros, see: https://docs.metasploit.com/
```

---

## Advanced Usage

### Scanning Large Networks
For networks larger than /24 (255+ hosts):
1. Use **arp-scan** (much faster than ping)
2. Select **thorough mode** for complete coverage
3. Be patient - large scans take time

### Custom Port Examples
```
Single ports:        80,443,8080
Port range:          1-1000
Mixed:               22,80-100,443,8000-9000
All common:          Leave empty and select option 4
All ports:           Select option 3
```

### Vulnerability Scanning Best Practices
1. **Start with version detection** (option 1)
2. **Add vulnerability scan** (option 13)
3. **Use timing template** (option 10) for faster results
4. **Enable verbose** (option 11) for detailed output
5. **Review CVEs** before launching Metasploit

---

## Security Best Practices

### Before Scanning
- Obtain **written permission**
- Document your scope
- Inform network administrators
- Plan your testing window
- Have an incident response plan

### During Scanning
- Start with **non-intrusive scans**
- Monitor for **system impacts**
- Respect rate limits
- Document all findings
- Stop if systems become unstable

### After Scanning
- **Report all vulnerabilities** (if founded)
- Provide remediation recommendations
- Delete sensitive data
- Follow responsible disclosure
- Archive logs securely

---

## Educational Use

CNIGT is perfect for:
- **Cybersecurity courses**
- **CTF competitions**
- **Home lab testing**
- **Learning network security**
- **Preparation for certifications** and more...


---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## Changelog

### v2.1.0 (Current)
- Added Metasploit integration
- CVE detection and highlighting
- Colored nmap output (green open ports)
- Post-scan interactive menu
- Custom port range option
- Session persistence
- Fixed '--script vuln' argument parsing

### v2.0.0
- Added user choice for discovery method
- Thorough arp-scan mode
- Enhanced nmap options
- Improved error handling

### v1.9.0
- Automatic subnet detection
- arp-scan integration
- Rich terminal UI
- Hostname resolution

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Legal Notice

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any damage or legal issues arising from the use or misuse of this tool.

**Users are solely responsible for:**
- Obtaining proper authorization
- Complying with local laws
- Any consequences of their actions

**Remember:** *With great power comes great responsibility.*

---

## Author

Made with love by **@KingsMover**

---

## Acknowledgments

- **nmap** - Network exploration and security auditing
- **arp-scan** - ARP scanning and fingerprinting tool
- **Metasploit** - Penetration testing framework
- **rich** - Beautiful terminal formatting library
- **The cybersecurity community** - For continuous learning and improvement

---

## Support

Found a bug? Have a feature request?
- [Open an issue](https://github.com/kingsmover/CNIGT/issues)
- [Request a feature](https://github.com/kingsmover/CNIGT/issues/new)

---

**Happy (Ethical) Hacking!**

---

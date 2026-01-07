# CNIGT v2.1.0 - Installation Guide

⚠️ LEGAL DISCLAIMER

This tool is for authorized security testing and educational purposes ONLY.

YOU MUST HAVE EXPLICIT PERMISSION to scan any network you do not own or administrate. Unauthorized network scanning is ILLEGAL in most jurisdictions, Violates computer fraud laws, May result in criminal charges, fines, or imprisonment and Could get you banned from networks/services.

Use CNIGT only on Your own home/office networks, Networks you have written permission to test, Your own lab/virtual environments and Educational sandboxes.

The developer assumes NO responsibility for misuse of this tool. Use ethically and legally.

## Prerequisites

This tool requires both Python packages and system tools to function properly.

---

## Python Requirements

### Step 1: Ensure Python 3 is installed
```bash
python3 --version
```
Should show Python 3.6 or higher.

### Step 2: Install pip (if not already installed)
```bash
sudo apt update
sudo apt install python3-pip -y
```

### Step 3: Install Python dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install rich
```

---

## System Tools Requirements

### Required Tools

#### 1. **nmap** (Required)
```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install nmap -y

# CentOS/RHEL/Fedora
sudo yum install nmap -y

# Arch Linux
sudo pacman -S nmap

# macOS
brew install nmap
```

Verify installation:
```bash
nmap --version
```

#### 2. **ping** (Usually pre-installed)
```bash
# If not installed (Debian/Ubuntu)
sudo apt install iputils-ping -y
```

Verify installation:
```bash
ping -V
```

---

### Optional but Recommended Tools

#### 3. **arp-scan** (Highly Recommended)
For fast and reliable host discovery with MAC addresses and vendor information.

```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install arp-scan -y

# CentOS/RHEL/Fedora
sudo yum install arp-scan -y

# Arch Linux
sudo pacman -S arp-scan

# macOS
brew install arp-scan
```

Verify installation:
```bash
arp-scan --version
```

**Note:** The script will offer to install arp-scan automatically if it's not found.

#### 4. **net-tools** (Optional)
Provides `ifconfig` command for network interface detection.

```bash
# Debian/Ubuntu/Kali
sudo apt install net-tools -y

# CentOS/RHEL/Fedora
sudo yum install net-tools -y

# Arch Linux
sudo pacman -S net-tools
```

Verify installation:
```bash
ifconfig
```

**Note:** The script will offer to install net-tools automatically if it's not found, or fall back to `ip` command.

---

## 🚀 Quick Installation (Debian/Ubuntu/Kali)

Run this one-liner to install everything:

```bash
sudo apt update && sudo apt install -y python3 python3-pip nmap arp-scan net-tools && pip install rich
```

---

##  Verify All Dependencies

Run this script to check if everything is installed:

```bash
#!/bin/bash

echo "Checking dependencies for CNIGT v2.1.0..."
echo "=========================================="

# Check Python
echo -n "Python3: "
if command -v python3 &> /dev/null; then
    echo " Installed ($(python3 --version))"
else
    echo " Not installed"
fi

# Check pip
echo -n "pip: "
if command -v pip &> /dev/null || command -v pip3 &> /dev/null; then
    echo " Installed"
else
    echo " Not installed"
fi

# Check rich
echo -n "rich (Python): "
if python3 -c "import rich" &> /dev/null; then
    echo " Installed"
else
    echo " Not installed (run: pip install rich)"
fi

# Check nmap
echo -n "nmap: "
if command -v nmap &> /dev/null; then
    echo " Installed ($(nmap --version | head -1))"
else
    echo " Not installed (REQUIRED)"
fi

# Check ping
echo -n "ping: "
if command -v ping &> /dev/null; then
    echo " Installed"
else
    echo " Not installed (REQUIRED)"
fi

# Check arp-scan
echo -n "arp-scan: "
if command -v arp-scan &> /dev/null; then
    echo " Installed ($(arp-scan --version | head -1))"
else
    echo "  Not installed (RECOMMENDED)"
fi

# Check ifconfig
echo -n "ifconfig: "
if command -v ifconfig &> /dev/null; then
    echo " Installed"
else
    echo "  Not installed (optional, will use 'ip' command)"
fi

# Check ip command
echo -n "ip: "
if command -v ip &> /dev/null; then
    echo " Installed"
else
    echo " Not installed"
fi

# Check arp
echo -n "arp: "
if command -v arp &> /dev/null; then
    echo " Installed"
else
    echo "  Not installed (needed for MAC address resolution)"
fi

echo "=========================================="
echo "Dependency check complete!"
```

Save this as `check_dependencies.sh`, make it executable, and run it:
```bash
chmod +x check_dependencies.sh
./check_dependencies.sh
```

---

## Running the Script

After installation:

```bash
# Make the script executable
chmod +x network_scan.py

# Run the script
sudo python3 network_scan.py
```

**Note:** `sudo` is required for:
- Running nmap with OS detection and certain scan types
- Running arp-scan
- Accessing raw network interfaces

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'rich'"
**Solution:**
```bash
pip install rich
# or
pip3 install rich
# or
python3 -m pip install rich
```

### Issue: "arp-scan: command not found"
**Solution:**
```bash
sudo apt install arp-scan
```
Or run the script and it will offer to install it automatically.

### Issue: "nmap: command not found"
**Solution:**
```bash
sudo apt install nmap
```

### Issue: Permission denied
**Solution:**
```bash
sudo python3 network_scan.py
```

### Issue: "ifconfig: command not found"
**Solution:** The script will automatically fall back to `ip` command or offer to install net-tools.

---

## Installation on Different Systems

### Kali Linux
```bash
sudo apt update
sudo apt install -y nmap arp-scan net-tools
pip install rich
```

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap arp-scan net-tools
pip3 install rich
```

### CentOS/RHEL/Fedora
```bash
sudo yum install -y python3 python3-pip nmap net-tools
sudo yum install arp-scan  # May need EPEL repository
pip3 install rich
```

### Arch Linux
```bash
sudo pacman -Syu
sudo pacman -S python python-pip nmap arp-scan net-tools
pip install rich
```

### macOS
```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python nmap arp-scan
pip3 install rich
```

---

## Permissions Note

Some operations require root privileges:
- **nmap** with OS detection (`-O`)
- **arp-scan** (requires raw socket access)
- Accessing certain network interfaces

Always run the script with `sudo`:
```bash
sudo python3 network_scan.py
```

---

## 📝 Summary

**Minimum Requirements:**
- Python 3.6+
- pip
- rich (Python package)
- nmap
- ping

**Recommended:**
- arp-scan (for better host discovery)
- net-tools (for ifconfig)

**Installation Time:** ~2-5 minutes

**Disk Space:** ~50-100 MB for all dependencies

---

## Ready to Use!

Once all dependencies are installed, you're ready to scan your network:

```bash
sudo python3 network_scan.py
```

Enjoy using CNIGT v2.1.0!

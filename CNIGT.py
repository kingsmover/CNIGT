#!/usr/bin/env python3

import subprocess
import sys
import threading
import time
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import track, Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.syntax import Syntax

banner = """

   █████████  ██████   █████ █████   █████████  ███████████
  ███░░░░░███░░██████ ░░███ ░░███   ███░░░░░███░█░░░███░░░█
 ███     ░░░  ░███░███ ░███  ░███  ███     ░░░ ░   ░███  ░
░███          ░███░░███░███  ░███ ░███             ░███
░███          ░███ ░░██████  ░███ ░███    █████    ░███
░░███     ███ ░███  ░░█████  ░███ ░░███  ░░███     ░███
 ░░█████████  █████  ░░█████ █████ ░░█████████     █████
  ░░░░░░░░░  ░░░░░    ░░░░░ ░░░░░   ░░░░░░░░░     ░░░░░
"""
Ccomment = """
                                  +Version 2.2.0
                                      ++Made With Love By @KingsMover
                                           +++Current Network Information Gathering Tool (CNIGT) is an automated
                                              tool that can help you to perform an active scan for your network 
                                              using nmap after listing to you all the online hosts on your current
                                              local network with automatic subnet detection...




"""


console = Console()
console.print(Panel(banner, style="bold bright_cyan", border_style="bright_magenta"))
console.print(Ccomment, style="dim cyan")

# Global variables to store scan context
last_network_range = None
last_alive_hosts = []
last_scanned_ip = None
vulnerabilities_found = []

def check_command(command):
    """
    Check if a command is available
    """
    try:
        subprocess.run(['which', command], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_arp_scan():
    """
    Check if arp-scan is installed
    """
    return check_command('arp-scan')

def check_metasploit():
    """
    Check if Metasploit is installed
    """
    return check_command('msfconsole')

def install_arp_scan():
    """
    Ask user if they want to install arp-scan
    """
    console.print("\n⚠️  'arp-scan' command not found.", style="bold yellow")
    console.print("arp-scan is recommended for faster and more reliable host discovery.", style="dim cyan")
    choice = input("Would you like to install arp-scan? (y/n): ").strip().lower()
    
    if choice in ['y', 'yes']:
        console.print("\n📦 Installing arp-scan...", style="cyan")
        try:
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', 'arp-scan'], check=True)
            console.print("✅ arp-scan installed successfully!\n", style="bold green")
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"❌ Failed to install arp-scan: {e}", style="bold red")
            return False
    return False

def install_metasploit():
    """
    Install Metasploit Framework
    """
    console.print("\n📦 Installing Metasploit Framework...", style="cyan")
    console.print("This may take several minutes...", style="dim yellow")
    
    try:
        # Download and run the Metasploit installer
        console.print("\n⬇️  Downloading Metasploit installer...", style="cyan")
        subprocess.run([
            'curl', 
            'https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb',
            '-o', '/tmp/msfinstall'
        ], check=True)
        
        subprocess.run(['chmod', '+x', '/tmp/msfinstall'], check=True)
        
        console.print("🚀 Running installer...", style="cyan")
        subprocess.run(['sudo', '/tmp/msfinstall'], check=True)
        
        console.print("✅ Metasploit installed successfully!\n", style="bold green")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Failed to install Metasploit: {e}", style="bold red")
        console.print("\n💡 Manual installation:", style="yellow")
        console.print("   Kali Linux: sudo apt install metasploit-framework", style="cyan")
        console.print("   Ubuntu/Debian: Follow https://docs.metasploit.com/", style="cyan")
        return False

def check_ifconfig():
    """
    Check if ifconfig is available
    """
    return check_command('ifconfig')

def install_net_tools():
    """
    Ask user if they want to install net-tools and install if yes
    """
    console.print("\n⚠️  'ifconfig' command not found.", style="bold yellow")
    choice = input("Would you like to install net-tools? (y/n): ").strip().lower()
    
    if choice in ['y', 'yes']:
        console.print("\n📦 Installing net-tools...", style="cyan")
        try:
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', 'net-tools'], check=True)
            console.print("✅ net-tools installed successfully!\n", style="bold green")
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"❌ Failed to install net-tools: {e}", style="bold red")
            return False
    return False

def get_network_info_ifconfig():
    """
    Get network information using ifconfig
    """
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        console.print(f"❌ Error running ifconfig: {e}", style="bold red")
        return None

def get_network_info_ip():
    """
    Get network information using 'ip a' command
    """
    try:
        result = subprocess.run(['ip', 'a'], capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        console.print(f"❌ Error running 'ip a': {e}", style="bold red")
        return None

def extract_network_info(network_info):
    """
    Extract IP addresses and subnet masks from network info output
    """
    cidr_pattern = r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})'
    netmask_hex_pattern = r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+netmask\s+(0x[0-9a-fA-F]+)'
    netmask_decimal_pattern = r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+netmask\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    
    networks = []
    
    cidr_matches = re.findall(cidr_pattern, network_info)
    for ip, prefix in cidr_matches:
        if not ip.startswith('127.'):
            try:
                network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                networks.append({
                    'ip': ip,
                    'network': str(network),
                    'netmask': str(network.netmask),
                    'cidr': prefix
                })
            except:
                pass
    
    hex_matches = re.findall(netmask_hex_pattern, network_info)
    for ip, netmask_hex in hex_matches:
        if not ip.startswith('127.'):
            try:
                netmask_int = int(netmask_hex, 16)
                netmask = '.'.join([str((netmask_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1)])
                network_obj = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                networks.append({
                    'ip': ip,
                    'network': str(network_obj),
                    'netmask': netmask,
                    'cidr': str(network_obj.prefixlen)
                })
            except:
                pass
    
    decimal_matches = re.findall(netmask_decimal_pattern, network_info)
    for ip, netmask in decimal_matches:
        if not ip.startswith('127.'):
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                networks.append({
                    'ip': ip,
                    'network': str(network),
                    'netmask': netmask,
                    'cidr': str(network.prefixlen)
                })
            except:
                pass
    
    return networks

def get_network_range():
    """
    Automatically detect network range from interface configuration
    """
    global last_network_range
    
    console.print("\n🔍 Detecting network interfaces and subnet masks...\n", style="bold bright_cyan")
    
    has_ifconfig = check_ifconfig()
    network_info = None
    
    if has_ifconfig:
        network_info = get_network_info_ifconfig()
        if network_info:
            console.print("📡 Network Interface Information (ifconfig):", style="bold green")
    else:
        if install_net_tools():
            network_info = get_network_info_ifconfig()
            if network_info:
                console.print("📡 Network Interface Information (ifconfig):", style="bold green")
        else:
            console.print("\n📡 Using 'ip a' command instead...", style="cyan")
            network_info = get_network_info_ip()
            if network_info:
                console.print("📡 Network Interface Information (ip a):", style="bold green")
    
    if not network_info:
        console.print("❌ Could not retrieve network information", style="bold red")
        return None
    
    console.print("=" * 80, style="dim white")
    console.print(network_info, style="white")
    console.print("=" * 80, style="dim white")
    
    networks = extract_network_info(network_info)
    
    if not networks:
        console.print("\n❌ Could not detect network configuration", style="bold red")
        return None
    
    console.print("\n✅ Detected Network(s):", style="bold green")
    
    net_table = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_yellow")
    net_table.add_column("No.", style="bold yellow", justify="center", width=5)
    net_table.add_column("IP Address", style="bold green", width=15)
    net_table.add_column("Network", style="bright_cyan", width=20)
    net_table.add_column("Netmask", style="bright_magenta", width=15)
    net_table.add_column("CIDR", style="dim white", width=10)
    
    for i, net in enumerate(networks, 1):
        net_table.add_row(str(i), net['ip'], net['network'], net['netmask'], f"/{net['cidr']}")
    
    console.print(net_table)
    
    console.print("\n" + "=" * 80, style="dim white")
    console.print("Select a network to scan:", style="bold bright_cyan")
    console.print(f"  Enter network number (1-{len(networks)}) to use auto-detected network", style="cyan")
    console.print("  Enter 'manual' to specify custom IP range", style="cyan")
    console.print("=" * 80, style="dim white")
    
    while True:
        choice = input("\nYour choice: ").strip().lower()
        
        if choice == 'manual':
            last_network_range = get_manual_ip_range()
            return last_network_range
        
        try:
            net_index = int(choice) - 1
            if 0 <= net_index < len(networks):
                selected_network = networks[net_index]['network']
                console.print(f"\n✅ Selected network: [bold green]{selected_network}[/bold green]", style="bold green")
                last_network_range = selected_network
                return selected_network
            else:
                console.print(f"❌ Invalid selection. Please choose 1-{len(networks)} or 'manual'", style="bold red")
        except ValueError:
            console.print("❌ Invalid input. Please enter a number or 'manual'", style="bold red")

def get_manual_ip_range():
    """
    Get manual IP range from user
    """
    console.print("\n📝 Manual IP Range Entry", style="bold bright_cyan")
    console.print("You can enter either:", style="dim cyan")
    console.print("  1. CIDR notation (e.g., 192.168.1.0/24)", style="cyan")
    console.print("  2. First three octets (e.g., 192.168.1)", style="cyan")
    
    while True:
        user_input = input("\nEnter network range: ").strip()
        
        if '/' in user_input:
            try:
                network = ipaddress.IPv4Network(user_input, strict=False)
                console.print(f"\n✅ Will scan network: [bold green]{network}[/bold green]", style="bold green")
                return str(network)
            except ValueError:
                console.print("❌ Invalid CIDR notation. Please try again.", style="bold red")
        else:
            parts = user_input.rstrip('.').split('.')
            
            if len(parts) == 3:
                try:
                    if all(0 <= int(part) <= 255 for part in parts):
                        base_ip = '.'.join(parts)
                        network = f"{base_ip}.0/24"
                        console.print(f"\n✅ Will scan network: [bold green]{network}[/bold green]", style="bold green")
                        return network
                    else:
                        console.print("❌ Each part must be between 0 and 255. Please try again.", style="bold red")
                except ValueError:
                    console.print("❌ Invalid format. Each part must be a number. Please try again.", style="bold red")
            else:
                console.print("❌ Invalid format. Please enter CIDR notation or 3 octets.", style="bold red")

def choose_discovery_method():
    """
    Ask user to choose between arp-scan and ping discovery
    """
    console.print("\n" + "=" * 80, style="dim white")
    console.print(Panel("[bold bright_cyan]🔍 HOST DISCOVERY METHOD[/bold bright_cyan]", border_style="bright_magenta"))
    
    comparison = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_yellow")
    comparison.add_column("Method", style="bold green", width=15)
    comparison.add_column("Speed", style="bright_cyan", width=15)
    comparison.add_column("Reliability", style="bright_magenta", width=15)
    comparison.add_column("Information", style="dim cyan", width=30)
    
    comparison.add_row("arp-scan", "⚡ Very Fast", "⭐⭐⭐⭐⭐ High", "IP, MAC, Vendor")
    comparison.add_row("ping", "🐌 Slower", "⭐⭐⭐ Medium", "IP only")
    
    console.print(comparison)
    console.print()
    
    has_arp_scan = check_arp_scan()
    
    if not has_arp_scan:
        console.print("⚠️  Note: arp-scan is not installed", style="bold yellow")
        console.print("   You can install it or use ping discovery", style="dim yellow")
    
    console.print("\n" + "-" * 80, style="dim white")
    console.print("Select discovery method:", style="bold bright_cyan")
    console.print("  [1] arp-scan (recommended - fast and shows MAC/Vendor)", style="cyan")
    console.print("  [2] ping (slower but works everywhere)", style="cyan")
    console.print("-" * 80, style="dim white")
    
    while True:
        choice = input("\nYour choice (1 or 2): ").strip()
        
        if choice == '1':
            if not has_arp_scan:
                if install_arp_scan():
                    return 'arp-scan'
                else:
                    console.print("\n⚠️  arp-scan not available. Falling back to ping.", style="bold yellow")
                    return 'ping'
            else:
                return 'arp-scan'
        elif choice == '2':
            return 'ping'
        else:
            console.print("❌ Invalid choice. Please enter 1 or 2.", style="bold red")

def choose_arp_scan_mode():
    """
    Ask user to choose between normal or thorough arp-scan
    """
    console.print("\n" + "=" * 80, style="dim white")
    console.print(Panel("[bold bright_cyan]🔧 ARP-SCAN MODE[/bold bright_cyan]", border_style="bright_magenta"))
    
    mode_table = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_yellow")
    mode_table.add_column("Mode", style="bold green", width=20)
    mode_table.add_column("Speed", style="bright_cyan", width=20)
    mode_table.add_column("Coverage", style="bright_magenta", width=35)
    
    mode_table.add_row("Normal (Fast)", "⚡ Very Fast (seconds)", "Good for most networks")
    mode_table.add_row("Thorough (Slow)", "🐌 Slower (more time)", "Best coverage - catches slow devices")
    
    console.print(mode_table)
    console.print()
    
    console.print("-" * 80, style="dim white")
    console.print("💡 [bold yellow]Tip:[/bold yellow] Use thorough mode if:", style="bright_yellow")
    console.print("   - Normal mode misses some devices", style="dim cyan")
    console.print("   - You have IoT devices or phones that respond slowly", style="dim cyan")
    console.print("   - You want maximum host discovery", style="dim cyan")
    console.print("-" * 80, style="dim white")
    
    console.print("\nSelect arp-scan mode:", style="bold bright_cyan")
    console.print("  [1] Normal (default - fast scan)", style="cyan")
    console.print("  [2] Thorough (slow scan with high retry)", style="cyan")
    
    while True:
        choice = input("\nYour choice (1 or 2): ").strip()
        
        if choice == '1':
            console.print("\n✅ Selected: Normal (fast) arp-scan mode", style="bold green")
            return 'normal'
        elif choice == '2':
            console.print("\n✅ Selected: Thorough (slow) arp-scan mode", style="bold green")
            return 'thorough'
        else:
            console.print("❌ Invalid choice. Please enter 1 or 2.", style="bold red")

def discover_hosts_arp_normal(network_range):
    """
    Discover hosts using arp-scan with normal/fast settings
    """
    console.print(f"🔍 Scanning network {network_range} using arp-scan (normal mode)...", style="bold bright_cyan")
    console.print("This should be quick...\n", style="dim white")
    
    start_time = time.time()
    alive_hosts = []
    
    try:
        result = subprocess.run(
            ['sudo', 'arp-scan', '--localnet', '--interface=auto'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        lines = result.stdout.split('\n')
        for line in lines:
            ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:]+)\s+(.*)$', line)
            if ip_match:
                ip = ip_match.group(1)
                mac = ip_match.group(2)
                vendor = ip_match.group(3).strip()
                alive_hosts.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'hostname': 'Unknown'
                })
                console.print(f"✅ Found: {ip} ({mac}) - {vendor}", style="bold green")
        
        elapsed = time.time() - start_time
        console.print(f"\n⏱️  Host discovery completed in {elapsed:.2f} seconds", style="bold yellow")
        
        alive_hosts.sort(key=lambda x: tuple(int(part) for part in x['ip'].split('.')))
        
        return alive_hosts
        
    except subprocess.TimeoutExpired:
        console.print("⚠️  arp-scan timed out.", style="bold yellow")
        return []
    except Exception as e:
        console.print(f"❌ Error running arp-scan: {e}", style="bold red")
        return []

def discover_hosts_arp_thorough(network_range):
    """
    Discover hosts using arp-scan with thorough/slow settings
    """
    console.print(f"🔍 Scanning network {network_range} using arp-scan (thorough mode)...", style="bold bright_cyan")
    console.print("This may take longer but will catch more devices...\n", style="dim white")
    
    start_time = time.time()
    alive_hosts = []
    
    try:
        console.print("Running with: --retry=10, --timeout=2000ms, --bandwidth=10000", style="dim cyan")
        result = subprocess.run(
            [
                'sudo', 'arp-scan',
                '--localnet',
                '--interface=auto',
                '--retry=10',
                '--timeout=2000',
                '--bandwidth=10000'
            ],
            capture_output=True,
            text=True,
            timeout=180
        )
        
        lines = result.stdout.split('\n')
        for line in lines:
            ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:]+)\s+(.*)$', line)
            if ip_match:
                ip = ip_match.group(1)
                mac = ip_match.group(2)
                vendor = ip_match.group(3).strip()
                alive_hosts.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'hostname': 'Unknown'
                })
                console.print(f"✅ Found: {ip} ({mac}) - {vendor}", style="bold green")
        
        console.print("\n🔍 Checking ARP cache for additional devices...", style="dim cyan")
        try:
            arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in arp_result.stdout.split('\n'):
                match = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+([0-9a-fA-F:]+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    if not any(host['ip'] == ip for host in alive_hosts) and mac != '<incomplete>':
                        alive_hosts.append({
                            'ip': ip,
                            'mac': mac,
                            'vendor': 'From ARP cache',
                            'hostname': 'Unknown'
                        })
                        console.print(f"✅ Found in ARP cache: {ip} ({mac})", style="bold yellow")
        except Exception as e:
            console.print(f"⚠️  Could not check ARP cache: {e}", style="dim yellow")
        
        elapsed = time.time() - start_time
        console.print(f"\n⏱️  Thorough host discovery completed in {elapsed:.2f} seconds", style="bold yellow")
        
        alive_hosts.sort(key=lambda x: tuple(int(part) for part in x['ip'].split('.')))
        
        return alive_hosts
        
    except subprocess.TimeoutExpired:
        console.print("⚠️  arp-scan timed out.", style="bold yellow")
        return []
    except Exception as e:
        console.print(f"❌ Error running arp-scan: {e}", style="bold red")
        return []

def get_hostname(ip):
    """
    Try to resolve hostname for an IP address
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

def ping_host(ip):
    """
    Ping a single host and return the IP if it responds
    """
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return ip
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass
    return None

def get_mac_from_arp(ip):
    """
    Try to get MAC address from ARP cache after ping
    """
    try:
        result = subprocess.run(
            ['arp', '-n', ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        lines = result.stdout.split('\n')
        for line in lines:
            if ip in line:
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                if match:
                    return match.group(0)
        return "N/A"
    except:
        return "N/A"

def discover_hosts_ping(network_range):
    """
    Discover hosts using ping
    """
    console.print(f"🔍 Scanning network {network_range} using ping...", style="bold bright_cyan")
    console.print("This may take a moment...\n", style="dim white")
    
    start_time = time.time()
    alive_hosts = []
    
    try:
        network = ipaddress.IPv4Network(network_range, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        
        if len(ip_list) > 1024:
            console.print(f"⚠️  Network is very large ({len(ip_list)} hosts). This may take a while...", style="bold yellow")
            console.print("Consider using arp-scan for better performance.", style="dim yellow")
    except ValueError as e:
        console.print(f"❌ Invalid network range: {e}", style="bold red")
        return []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning hosts...", total=len(ip_list))
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
            
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    mac = get_mac_from_arp(result)
                    alive_hosts.append({
                        'ip': result,
                        'mac': mac,
                        'vendor': 'N/A' if mac == 'N/A' else 'Check ARP',
                        'hostname': 'Unknown'
                    })
                    console.print(f"✅ Found: {result}" + (f" ({mac})" if mac != "N/A" else ""), style="bold green")
                progress.advance(task)
    
    elapsed = time.time() - start_time
    console.print(f"\n⏱️  Host discovery completed in {elapsed:.2f} seconds", style="bold yellow")
    
    alive_hosts.sort(key=lambda x: tuple(int(part) for part in x['ip'].split('.')))
    
    return alive_hosts

def discover_hosts(network_range):
    """
    Main host discovery function
    """
    global last_alive_hosts
    
    method = choose_discovery_method()
    
    if method == 'arp-scan':
        mode = choose_arp_scan_mode()
        
        if mode == 'normal':
            last_alive_hosts = discover_hosts_arp_normal(network_range)
        else:
            last_alive_hosts = discover_hosts_arp_thorough(network_range)
    else:
        last_alive_hosts = discover_hosts_ping(network_range)
    
    return last_alive_hosts

def display_hosts_table(alive_hosts):
    """
    Display found hosts in a nice table
    """
    console.print(f"\n✅ Found {len(alive_hosts)} responsive host(s)\n", style="bold green")
    
    table = Table(
        title="🌐 Discovered Hosts",
        box=box.ROUNDED,
        style="cyan",
        header_style="bold bright_cyan"
    )
    table.add_column("No.", style="bold yellow", justify="center", width=5)
    table.add_column("IP Address", style="bold green", width=15)
    table.add_column("MAC Address", style="bright_magenta", width=20)
    table.add_column("Vendor", style="dim cyan", width=30)
    table.add_column("Hostname", style="bright_white", width=25)
    
    console.print("🔍 Resolving hostnames...", style="dim cyan")
    
    for i, host in enumerate(alive_hosts, 1):
        if host['hostname'] == 'Unknown':
            host['hostname'] = get_hostname(host['ip'])
        
        table.add_row(
            str(i),
            host['ip'],
            host['mac'],
            host['vendor'][:28] + '..' if len(host['vendor']) > 30 else host['vendor'],
            host['hostname']
        )
    
    console.print(table)

def get_nmap_options():
    """
    Display nmap options and get user selection
    """
    console.print(Panel(
        "[bold bright_cyan]🔧 NMAP SCAN OPTIONS[/bold bright_cyan]",
        border_style="bright_magenta"
    ))
    
    options = {
        '1': {
            'flag': '-sV',
            'name': 'Service Version Detection',
            'description': 'Detect service versions running on open ports'
        },
        '2': {
            'flag': '-O',
            'name': 'OS Detection',
            'description': 'Detect operating system (requires sudo)'
        },
        '3': {
            'flag': '-p-',
            'name': 'Scan All Ports',
            'description': 'Scan all 65535 ports (slower but comprehensive)'
        },
        '4': {
            'flag': '-p 1-1000',
            'name': 'Scan Common Ports',
            'description': 'Scan ports 1-1000 only (faster)'
        },
        '5': {
            'flag': '-F',
            'name': 'Fast Scan',
            'description': 'Scan only top 100 most common ports (very fast)'
        },
        '6': {
            'flag': '-p',
            'name': 'Custom Port Range',
            'description': 'Specify custom port range (e.g., 80,443 or 1-1000)'
        },
        '7': {
            'flag': '-sC',
            'name': 'Default Scripts',
            'description': 'Run default NSE scripts for vulnerability detection'
        },
        '8': {
            'flag': '-A',
            'name': 'Aggressive Scan',
            'description': 'Enable OS detection, version detection, script scanning, and traceroute'
        },
        '9': {
            'flag': '--open',
            'name': 'Show Only Open Ports',
            'description': 'Display only open ports in results'
        },
        '10': {
            'flag': '-T4',
            'name': 'Timing Template (T4)',
            'description': 'Aggressive timing - faster scan (T0-T5, default T3)'
        },
        '11': {
            'flag': '-v',
            'name': 'Verbose Output',
            'description': 'Show more detailed information during scan'
        },
        '12': {
            'flag': '-Pn',
            'name': 'Skip Ping',
            'description': 'Skip host discovery, treat host as online'
        },
        '13': {
            'flag': ['--script', 'vuln'],
            'name': 'Vulnerability Scan',
            'description': 'Search for known vulnerabilities (CVEs)'
        }
    }
    
    opt_table = Table(box=box.SIMPLE, show_header=True, header_style="bold bright_yellow")
    opt_table.add_column("No.", style="bold yellow", justify="center", width=5)
    opt_table.add_column("Option Name", style="bold green", width=30)
    opt_table.add_column("Description", style="bright_cyan", width=50)
    
    for key in sorted(options.keys(), key=int):
        opt = options[key]
        opt_table.add_row(key, opt['name'], opt['description'])
    
    console.print(opt_table)
    
    console.print("\n" + "-" * 90, style="dim white")
    console.print("💡 [bold yellow]Tips:[/bold yellow]", style="bright_yellow")
    console.print("   - Enter multiple numbers separated by spaces (e.g., 1 2 9)", style="dim cyan")
    console.print("   - Option 8 (-A) includes options 1, 2, and 7 automatically", style="dim cyan")
    console.print("   - Options 3, 4, 5, 6 are mutually exclusive (choose one)", style="dim cyan")
    console.print("   - Press Enter without input for quick scan (no options)", style="dim cyan")
    console.print("-" * 90, style="dim white")
    
    while True:
        user_input = input("\nEnter option numbers (or press Enter for basic scan): ").strip()
        
        if user_input == "":
            console.print("\n✅ Running basic nmap scan (no extra options)", style="bold green")
            return []
        
        selected = user_input.split()
        
        valid = True
        for choice in selected:
            if choice not in options:
                console.print(f"❌ Invalid option: {choice}. Please try again.", style="bold red")
                valid = False
                break
        
        if not valid:
            continue
        
        port_options = set(selected) & {'3', '4', '5', '6'}
        if len(port_options) > 1:
            console.print("⚠️  Warning: Options 3, 4, 5, and 6 are mutually exclusive.", style="bold yellow")
            console.print("   Please select only one port scanning option.", style="yellow")
            continue
        
        selected_flags = []
        selected_names = []
        custom_ports = None
        
        for choice in selected:
            if choice == '6':
                port_input = input("Enter port range (e.g., 80,443 or 1-1000 or 80-100,443,8080): ").strip()
                if port_input:
                    selected_flags.extend(['-p', port_input])
                    selected_names.append(f'Custom Ports ({port_input})')
                else:
                    console.print("❌ No port range specified. Skipping custom ports.", style="bold red")
            else:
                flag = options[choice]['flag']
                # Handle both string and list flags
                if isinstance(flag, list):
                    selected_flags.extend(flag)
                else:
                    selected_flags.append(flag)
                selected_names.append(options[choice]['name'])
        
        console.print(f"\n✅ Selected options: [bold green]{', '.join(selected_names)}[/bold green]")
        return selected_flags

def parse_nmap_output_with_colors(line, vuln_scan=False):
    """
    Parse nmap output and colorize open ports and vulnerabilities
    """
    global vulnerabilities_found
    
    # Color open ports green
    if '/tcp' in line or '/udp' in line:
        if 'open' in line:
            console.print(line, style="bold green")
            return True
        else:
            print(line)
            return False
    # Detect and highlight vulnerabilities
    elif vuln_scan and 'VULNERABLE' in line.upper():
        console.print(line, style="bold red")
        # Try to extract CVE
        cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(1)
            if cve_id not in vulnerabilities_found:
                vulnerabilities_found.append(cve_id)
                console.print(f"  🚨 [bold red]Found vulnerability: {cve_id}[/bold red]")
        return True
    elif vuln_scan and re.search(r'CVE-\d{4}-\d+', line, re.IGNORECASE):
        console.print(line, style="yellow")
        cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(1)
            if cve_id not in vulnerabilities_found:
                vulnerabilities_found.append(cve_id)
        return True
    else:
        print(line)
        return False

def run_nmap_scan(ip, nmap_options=None):
    """
    Run nmap scan on the given IP with user-selected options
    """
    global last_scanned_ip, vulnerabilities_found
    
    last_scanned_ip = ip
    vulnerabilities_found = []
    
    console.print(f"\n🔎 Starting scan on [bold green]{ip}[/bold green]...", style="bright_cyan")
    console.print("=" * 60, style="dim white")
    
    start_time = time.time()
    
    nmap_cmd = ['sudo', 'nmap']
    
    vuln_scan = False
    if nmap_options:
        # Check if vulnerability scan is enabled
        for i, opt in enumerate(nmap_options):
            if opt == '--script' and i + 1 < len(nmap_options) and nmap_options[i + 1] == 'vuln':
                vuln_scan = True
                break
        nmap_cmd.extend(nmap_options)
    
    nmap_cmd.append(ip)
    
    try:
        console.print(f"Running: [dim cyan]{' '.join(nmap_cmd)}[/dim cyan]")
        console.print("-" * 60, style="dim white")
        
        if vuln_scan:
            console.print("🔍 [bold yellow]Vulnerability scan enabled - this may take longer...[/bold yellow]\n")
        
        process = subprocess.Popen(
            nmap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        for line in process.stdout:
            parse_nmap_output_with_colors(line.rstrip(), vuln_scan)
        
        process.wait()
        
        elapsed = time.time() - start_time
        
        if process.returncode == 0:
            console.print(f"\n✅ Scan completed successfully for {ip}", style="bold green")
            console.print(f"⏱️  Scan took {elapsed:.2f} seconds", style="bold yellow")
            
            if vuln_scan and vulnerabilities_found:
                console.print(f"\n🚨 [bold red]Found {len(vulnerabilities_found)} CVE(s):[/bold red]")
                for cve in vulnerabilities_found:
                    console.print(f"   • {cve}", style="red")
        else:
            console.print(f"\n❌ Scan failed for {ip} (return code: {process.returncode})", style="bold red")
            
    except FileNotFoundError:
        console.print("❌ Error: nmap not found. Please install nmap:", style="bold red")
        console.print("   Ubuntu/Debian: sudo apt-get install nmap", style="yellow")
        console.print("   CentOS/RHEL: sudo yum install nmap", style="yellow")
        console.print("   macOS: brew install nmap", style="yellow")
    except KeyboardInterrupt:
        console.print(f"\n⚠️  Scan interrupted by user for {ip}", style="bold yellow")
    except Exception as e:
        console.print(f"❌ Error scanning {ip}: {str(e)}", style="bold red")

def post_scan_menu():
    """
    Display menu after scan completion for next actions
    """
    console.print("\n" + "=" * 80, style="dim white")
    console.print(Panel(
        "[bold bright_cyan]📋 WHAT WOULD YOU LIKE TO DO NEXT?[/bold bright_cyan]",
        border_style="bright_magenta"
    ))
    
    menu_table = Table(box=box.ROUNDED, show_header=False)
    menu_table.add_column("Option", style="bold yellow", width=10)
    menu_table.add_column("Description", style="cyan", width=60)
    
    menu_table.add_row("[1]", "Re-run host discovery (ping)")
    menu_table.add_row("[2]", "Re-run host discovery (arp-scan)")
    menu_table.add_row("[3]", f"Scan last IP again ({last_scanned_ip}) with different nmap options")
    menu_table.add_row("[4]", "Scan a different IP from discovered hosts")
    menu_table.add_row("[5]", "Scan a custom IP address")
    
    if vulnerabilities_found:
        menu_table.add_row("[6]", "🎯 Launch Metasploit (vulnerabilities found!)", style="bold red")
        menu_table.add_row("[7]", "Exit tool")
    else:
        menu_table.add_row("[6]", "Launch Metasploit")
        menu_table.add_row("[7]", "Exit tool")
    
    console.print(menu_table)
    console.print("=" * 80, style="dim white")
    
    while True:
        choice = input("\nYour choice: ").strip()
        
        if choice == '1':
            return 'rediscover_ping'
        elif choice == '2':
            return 'rediscover_arp'
        elif choice == '3':
            if last_scanned_ip:
                return 'rescan_last'
            else:
                console.print("❌ No previous scan found.", style="bold red")
        elif choice == '4':
            if last_alive_hosts:
                return 'scan_from_list'
            else:
                console.print("❌ No discovered hosts available.", style="bold red")
        elif choice == '5':
            return 'scan_custom_ip'
        elif choice == '6':
            return 'launch_metasploit'
        elif choice == '7':
            return 'exit'
        else:
            console.print("❌ Invalid choice. Please enter a number from the menu.", style="bold red")

def launch_metasploit():
    """
    Launch Metasploit Framework with disclaimer
    """
    console.print("\n" + "=" * 80, style="dim white")
    console.print(Panel(
        "[bold red]⚠️  METASPLOIT DISCLAIMER ⚠️[/bold red]\n\n"
        "[yellow]IMPORTANT: Only use Metasploit on systems you own or have explicit written "
        "permission to test. Unauthorized access to computer systems is illegal and punishable "
        "by law.\n\n"
        "By continuing, you acknowledge that you:\n"
        "• Have authorization to test the target system\n"
        "• Understand the legal implications\n"
        "• Take full responsibility for your actions[/yellow]",
        border_style="red",
        title="[bold red]LEGAL WARNING[/bold red]"
    ))
    console.print("=" * 80, style="dim white")
    
    choice = input("\nDo you want to continue? (y/n): ").strip().lower()
    
    if choice not in ['y', 'yes']:
        console.print("\n✅ Metasploit launch cancelled.", style="bold green")
        return False
    
    # Check if Metasploit is installed
    if not check_metasploit():
        console.print("\n⚠️  Metasploit Framework is not installed.", style="bold yellow")
        install_choice = input("Would you like to install it? (y/n): ").strip().lower()
        
        if install_choice in ['y', 'yes']:
            if not install_metasploit():
                console.print("\n❌ Failed to install Metasploit.", style="bold red")
                return False
        else:
            console.print("\n✅ Metasploit installation cancelled.", style="bold green")
            return False
    
    # Display found vulnerabilities if any
    if vulnerabilities_found:
        console.print("\n💡 [bold yellow]Vulnerabilities found in previous scan:[/bold yellow]")
        for cve in vulnerabilities_found:
            console.print(f"   • [red]{cve}[/red] - Search in Metasploit: search {cve}")
    
    console.print("\n🚀 [bold green]Launching Metasploit Framework...[/bold green]\n")
    console.print("💡 [yellow]Useful commands:[/yellow]")
    console.print("   • search <CVE-ID>  - Search for exploits")
    console.print("   • use <exploit>    - Select an exploit")
    console.print("   • show options     - View required options")
    console.print("   • set RHOSTS <IP>  - Set target IP")
    console.print("   • exploit          - Run the exploit")
    console.print("   • exit             - Exit Metasploit\n")
    
    time.sleep(2)
    
    try:
        subprocess.run(['sudo', 'msfconsole'])
    except KeyboardInterrupt:
        console.print("\n\n⚠️  Metasploit interrupted.", style="bold yellow")
    except Exception as e:
        console.print(f"\n❌ Error launching Metasploit: {e}", style="bold red")
    
    return True

def main():
    """
    Main function to orchestrate the network discovery and scanning
    """
    global last_network_range, last_alive_hosts, last_scanned_ip
    
    console.print(Panel(
        "[bold bright_cyan]🌐 Network Discovery and Port Scanner[/bold bright_cyan]",
        border_style="bright_magenta"
    ))
    
    try:
        # Step 1: Get network range
        if not last_network_range:
            network_range = get_network_range()
            
            if not network_range:
                console.print("❌ Could not determine network range. Exiting.", style="bold red")
                return
        else:
            network_range = last_network_range
        
        # Step 2: Discover alive hosts
        if not last_alive_hosts:
            alive_hosts = discover_hosts(network_range)
            
            if not alive_hosts:
                console.print(f"\n❌ No responsive hosts found in {network_range}", style="bold red")
                return
            
            display_hosts_table(alive_hosts)
        else:
            alive_hosts = last_alive_hosts
            display_hosts_table(alive_hosts)
        
        # Step 3: Get nmap options
        nmap_options = get_nmap_options()
        
        # Step 4: Interactive host selection
        while True:
            console.print("\n" + "=" * 70, style="dim white")
            console.print("[bold bright_cyan]Select a host to scan with nmap:[/bold bright_cyan]")
            console.print(f"  Enter host number (1-{len(alive_hosts)})", style="cyan")
            console.print("  Enter 'all' to scan all hosts", style="cyan")
            console.print("  Enter 'options' to change nmap options", style="cyan")
            console.print("  Enter 'quit' or 'q' to exit", style="cyan")
            console.print("-" * 70, style="dim white")
            
            choice = input("Your choice: ").strip().lower()
            
            if choice in ['quit', 'q', 'exit']:
                console.print("👋 Goodbye!", style="bold green")
                break
            elif choice == 'options':
                nmap_options = get_nmap_options()
            elif choice == 'all':
                console.print(f"\n🚀 Scanning all {len(alive_hosts)} hosts...", style="bold bright_cyan")
                for host in alive_hosts:
                    run_nmap_scan(host['ip'], nmap_options)
                    console.print("\n" + "=" * 70, style="dim white")
                
                # After scanning all, show post-scan menu
                action = post_scan_menu()
                if not handle_post_scan_action(action, network_range, alive_hosts, nmap_options):
                    break
            else:
                try:
                    host_index = int(choice) - 1
                    if 0 <= host_index < len(alive_hosts):
                        selected_host = alive_hosts[host_index]['ip']
                        run_nmap_scan(selected_host, nmap_options)
                        
                        # Show post-scan menu after single scan
                        action = post_scan_menu()
                        if not handle_post_scan_action(action, network_range, alive_hosts, nmap_options):
                            break
                    else:
                        console.print(f"❌ Invalid selection. Please choose 1-{len(alive_hosts)}", style="bold red")
                except ValueError:
                    console.print("❌ Invalid input. Please enter a number, 'all', 'options', or 'quit'", style="bold red")
                    
    except KeyboardInterrupt:
        console.print("\n\n⚠️  Program interrupted by user. Goodbye!", style="bold yellow")
    except Exception as e:
        console.print(f"\n❌ Unexpected error: {str(e)}", style="bold red")

def handle_post_scan_action(action, network_range, alive_hosts, current_nmap_options):
    """
    Handle post-scan menu actions
    """
    global last_network_range, last_alive_hosts, last_scanned_ip
    
    if action == 'rediscover_ping':
        console.print("\n🔄 Re-running host discovery with ping...\n", style="bold cyan")
        new_hosts = discover_hosts_ping(network_range)
        if new_hosts:
            last_alive_hosts = new_hosts
            display_hosts_table(new_hosts)
        return True
        
    elif action == 'rediscover_arp':
        console.print("\n🔄 Re-running host discovery with arp-scan...\n", style="bold cyan")
        mode = choose_arp_scan_mode()
        if mode == 'normal':
            new_hosts = discover_hosts_arp_normal(network_range)
        else:
            new_hosts = discover_hosts_arp_thorough(network_range)
        if new_hosts:
            last_alive_hosts = new_hosts
            display_hosts_table(new_hosts)
        return True
        
    elif action == 'rescan_last':
        if last_scanned_ip:
            console.print(f"\n🔄 Re-scanning {last_scanned_ip}...\n", style="bold cyan")
            new_options = get_nmap_options()
            run_nmap_scan(last_scanned_ip, new_options)
            return True
        return True
        
    elif action == 'scan_from_list':
        display_hosts_table(alive_hosts)
        console.print("\nSelect a host to scan:", style="bold bright_cyan")
        try:
            choice = int(input("Enter host number: ").strip()) - 1
            if 0 <= choice < len(alive_hosts):
                run_nmap_scan(alive_hosts[choice]['ip'], current_nmap_options)
                return True
            else:
                console.print("❌ Invalid selection.", style="bold red")
                return True
        except ValueError:
            console.print("❌ Invalid input.", style="bold red")
            return True
            
    elif action == 'scan_custom_ip':
        custom_ip = input("\nEnter IP address to scan: ").strip()
        # Validate IP
        try:
            ipaddress.IPv4Address(custom_ip)
            new_options = get_nmap_options()
            run_nmap_scan(custom_ip, new_options)
            return True
        except ValueError:
            console.print("❌ Invalid IP address format.", style="bold red")
            return True
            
    elif action == 'launch_metasploit':
        launch_metasploit()
        return True
        
    elif action == 'exit':
        console.print("\n👋 Goodbye!", style="bold green")
        return False
    
    return True

if __name__ == "__main__":
    try:
        subprocess.run(['which', 'ping'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("❌ Error: 'ping' command not found.", style="bold red")
        console.print("This script requires the 'ping' utility to be installed.", style="yellow")
        sys.exit(1)
    
    if not check_command('nmap'):
        console.print("❌ Error: 'nmap' command not found.", style="bold red")
        console.print("This script requires nmap to be installed:", style="yellow")
        console.print("   Ubuntu/Debian: sudo apt-get install nmap", style="cyan")
        console.print("   CentOS/RHEL: sudo yum install nmap", style="cyan")
        console.print("   macOS: brew install nmap", style="cyan")
        sys.exit(1)
    
    console.print("⚠️  Note: This script will use 'sudo' for nmap and arp-scan", style="bold yellow")
    console.print("   You may be prompted for your password during execution.\n", style="dim yellow")
    
    main()

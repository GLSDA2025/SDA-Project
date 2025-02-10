import subprocess
import re
from scapy.all import ARP, Ether, srp, sr1, TCP, IP
import socket

def get_ip_and_subnet():
    try:
        result = subprocess.run(['ip', '-o', '-4', 'addr', 'show'], capture_output=True, text=True)
        interfaces = result.stdout.split('\n')
        for line in interfaces:
            if 'inet' in line and 'scope global' in line:
                parts = line.strip().split()
                ip_cidr = parts[3]
                ip, cidr = ip_cidr.split('/')
                return ip, cidr
        return None, None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None, None

def host_discovery(ip, cidr):
    try:
        network = f"{ip}/{cidr}"
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        active_hosts = [rcv.psrc for snd, rcv in result]
        return active_hosts
    except Exception as e:
        print(f"[!] Host discovery failed: {e}")
        return []

def port_scan(host, ports):
    open_ports = []
    for port in ports:
        try:
            response = sr1(IP(dst=host)/TCP(dport=port, flags='S'), timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                open_ports.append(port)
                sr1(IP(dst=host)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
        except:
            continue
    return open_ports

def banner_grab(host, port):
    try:
        if port == 80 or port == 443:
            protocol = "http" if port == 80 else "https"
            response = requests.get(f"{protocol}://{host}", timeout=2)
            server_header = response.headers.get("Server", "No banner")
            return server_header
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
                banner = s.recv(1024).decode().strip()
                return banner
    except:
        return None

if __name__ == "_main_":
    kali_ip, cidr = get_ip_and_subnet()
    if not kali_ip or not cidr:
        print("Failed to detect Kali IP/subnet. Check network settings.")
        exit()
    print(f"[+] Kali IP: {kali_ip}/{cidr}")
    active_hosts = host_discovery(kali_ip, cidr)
    print(f"[+] Active Hosts: {active_hosts}")
    ports = [21, 22, 80, 443, 8000, 8080, 3306, 3389, 445, 53, 161]
    for host in active_hosts:
        if host == kali_ip:
            continue
        print(f"\n[+] Scanning {host}")
        open_ports = port_scan(host, ports)
        print(f"Open Ports: {open_ports}")
        for port in open_ports:
            banner = banner_grab(host, port)
            print(f"Port {port} Banner: {banner if banner else 'No banner'}")
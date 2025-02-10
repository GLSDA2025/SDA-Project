import scapy.all as scapy
import socket
import requests
import concurrent.futures
from tabulate import tabulate
from tqdm import tqdm

# Get the local machine's IP
def get_my_ip():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip


def get_network_range(network='10.0.0.0/24'):
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    
    network_ips = []
    for element in answered_list:
        ip = element[1].psrc
        if ip != get_my_ip():
            network_ips.append(ip)
    return network_ips

#Port scanning using Scapy
def scan_ports(ip):
    open_ports = []
    for port in range(20, 10000):  
        syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(syn_packet, timeout=10, verbose=False)
        
        if response:
            if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 18:
                open_ports.append(port)
    return open_ports


def grab_banner(ip, port):
    try:
        # Banner Grabbing
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return None


def get_cves_for_service(service_name):
    if not service_name:
        return []

    normalized_service_name = service_map.get(service_name.lower(), service_name.lower())
    cve_url = f'https://cve.circl.lu/api/cve/{normalized_service_name}'

    try:
        response = requests.get(cve_url)
        if response and response.status_code == 200:
            cves = response.json().get('cve', [])
            return cves
        else:
            print(f"Failed to retrieve CVE data for {service_name}. Response code: {response.status_code}")
    except Exception as e:
        print(f"Error while fetching CVEs for {service_name}: {e}")
    
    return []


def scan_host(ip):
    open_ports = scan_ports(ip)
    service_info = []
    
    for port in open_ports:
        banner = grab_banner(ip, port)
        if banner:
            service_name = banner.split()[0].lower()
            

            if service_name not in ["http", "ftp", "ssh", "smtp", "telnet"]:
                service_name = banner.split()[1].lower() if len(banner.split()) > 1 else "unknown_service"

            cves = get_cves_for_service(service_name)
            if cves:
                for cve in cves:
                    service_info.append({
                        'IP': ip,
                        'Port': port,
                        'Banner': banner,
                        'CVEs': cve.get('id', 'No CVEs found')
                    })
            else:
                service_info.append({
                    'IP': ip,
                    'Port': port,
                    'Banner': banner,
                    'CVEs': 'No CVEs found'
                })
    
    return service_info

def collect_data_parallel():
    network_ips = get_network_range('10.0.0.0/24')
    all_service_info = []
    
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(tqdm(executor.map(scan_host, network_ips), total=len(network_ips), desc="Scanning Hosts"))
            for result in results:
                all_service_info.extend(result)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return []

    return all_service_info


def main():
    all_data = collect_data_parallel()

    headers = ['IP', 'Port', 'Banner', 'CVEs']
    table_data = []

    for data in all_data:
        table_data.append([data['IP'], data['Port'], data['Banner'], data.get('CVEs', 'No CVEs')])
    
    print("\nResults:")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

if __name__ == '__main__':
    main()

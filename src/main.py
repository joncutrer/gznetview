import argparse
import nmap
import scapy.all as scapy
import socket
from manuf import manuf

def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(network, arguments='-sn')
    hosts = nm.all_hosts()
    return hosts

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    return answered_list[0][1].hwsrc if answered_list else 'Unknown'

def get_hostname(ip):
    try:
        host_name, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        host_name = 'Unknown'
    return host_name

def get_manufacturer(mac):
    p = manuf.MacParser()
    manufacturer = p.get_manuf(mac)
    return manufacturer if manufacturer else 'Unknown'

def print_hosts_info(hosts):
    print("IP Address,MAC Address,Host Name,Manufacturer")  # Header row
    for host in hosts:
        mac = get_mac(host)
        host_name = get_hostname(host)
        try:
            manufacturer = get_manufacturer(mac)
        except ValueError:
            manufacturer = 'Unknown'
        print(f'{host},{mac},{host_name},{manufacturer}')  # Data rows

def main():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument('network', type=str, help='The network to scan in CIDR notation (e.g., 192.168.1.0/24)')
    args = parser.parse_args()

    hosts = scan_network(args.network)
    print_hosts_info(hosts)

if __name__ == "__main__":
    main()

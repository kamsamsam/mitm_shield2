from scapy.all import sniff, ARP, IP, Ether, TCP, DHCP, DNS, DNSRR, sr1
from scapy.layers.http import HTTPRequest
import subprocess

def getmacbyip(ip):
    """
    Returns the MAC address for a given IP address using ARP requests.
    If the IP address does not exist or no response is received, logs the failure and returns None.
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    arp_response = sr1(arp_request, timeout=1, verbose=False)
    if arp_response:
        return arp_response.hwsrc
    else:
        print(f"WARNING: No ARP response received for IP {ip}.")
        return None

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        response_mac = packet[ARP].hwsrc
        real_mac = getmacbyip(packet[ARP].psrc)
        if real_mac and real_mac != response_mac:
            alert = f"[!] Detected ARP Spoofing: {packet[ARP].psrc} has incorrect MAC {response_mac}"
            print(alert)
            block_ip(packet[ARP].psrc)
        elif not real_mac:
            print(f"Failed to verify ARP for IP {packet[ARP].psrc}, no MAC address found.")

def detect_dhcp_spoofing(packet):
    if packet.haslayer(DHCP):
        options = packet[DHCP].options
        for option in options:
            if option[0] == 'message-type' and option[1] == 2:  # DHCP Offer
                server_id = get_option(options, 'server_id')
                if not verify_dhcp_server(server_id):
                    alert = f"[!] Detected DHCP Spoofing from server {server_id}"
                    print(alert)
                    block_ip(packet[IP].src)

def detect_dns_spoofing(packet):
    if packet.haslayer(DNSRR):
        rrname = packet[DNSRR].rrname.decode().strip('.')
        expected_ip = '93.184.216.34'  # Example IP for example.com
        if rrname == 'example.com.' and packet[DNSRR].rdata != expected_ip:
            alert = f"[!] DNS Spoofing Detected: {rrname} points to {packet[DNSRR].rdata}"
            print(alert)
            block_ip(packet[IP].src)

def detect_session_hijacking(packet):
    if packet.haslayer(TCP) and packet.haslayer(HTTPRequest):
        if 'cookie' in packet:
            cookies = packet[HTTPRequest].Cookie.decode()
            alert = f"[!] Session Hijacking possible on {packet[HTTPRequest].Host.decode()} with cookies {cookies}"
            print(alert)

def block_ip(ip):
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(command, shell=True)
    print(f"[+] IP blocked successfully: {ip}")

def get_option(dhcp_options, key):
    for option in dhcp_options:
        if option[0] == key:
            return option[1]
    return None

def verify_dhcp_server(server_id):
    return server_id == 'Trusted DHCP Server IP'

def main():
    print("[*] Starting enhanced network monitor...")
    def custom_action(packet):
        detect_arp_spoofing(packet)
        detect_dhcp_spoofing(packet)
        detect_dns_spoofing(packet)
        detect_session_hijacking(packet)
    sniff(store=False, prn=custom_action)

if __name__ == "__main__":
    main()


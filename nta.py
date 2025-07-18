#!/usr/bin/env python3
"""
Network Traffic Analyzer - Basic project
Author: Diego
Date: 28.6.2025

This project will help you learn the basics of network analysis.
"""

import os
import re
import time
import scapy.all as scapy
from colorama import init, Fore, Style

init(autoreset=True)

# Dictionary: port -> protocol (TCP and UDP)
PROTO_STAT = {}
PORT_PROTOCOLS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    179: "BGP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-ALT",
    # ...add more as needed
}
TLS_HANDSHAKE_TYPES = {
    0: "HelloRequest",
    1: "Client Hello",
    2: "Server Hello",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
    21: "Certificate URL",
    22: "Certificate Status",
    23: "Supplemental Data",
    # ...add more as needed
}
PROTOCOL_HISTORY = []


def main():
    """
    Main program function
    """
    print("🔍 Network Traffic Analyzer - Starting!")
    print("=" * 50)

    interfaces = show_network_interfaces()

    if not interfaces:
        print("No interfaces found...")
        return

    option = interfaces[choose_option(len(interfaces)) - 1]
    print(f"Selected interface: {option}")
    capture_packets(option)
    if not PROTOCOL_HISTORY:
        return
    save_option = ask_save(
        "Do you want to save your output ? y/n: "
    )
    stats_option = ask_save(
        "Do you want to add statistic to end of your file ? y/n: "
    )
    if save_option == "y":
        file_name = input("Choose your filename: ")
        try:
            with open(file_name, "w") as file:
                for line in PROTOCOL_HISTORY:
                    file.write(line + "\n")
                print(50 * "-")
                if stats_option == "y":
                    file.write(50 * "-")
                    file.write("STATS")
                    file.write(50 * "-" + "\n")
                    for proto, number in PROTO_STAT.items():
                        file.write(f"{proto}: {number}\n")
                    for proto, number in PROTO_STAT.items():
                        print(f"{proto}: {number}")
            print(f"Output saved to {file_name}")
        except Exception as e:
            print(f"Error saving file: {e}")
            print("Try different file name!")


def show_network_interfaces():
    """
    Function to display available network interfaces
    """
    interfaces = scapy.get_if_list()
    print("\n Available network interfaces:")
    print("-" * 40)
    for index, inter in enumerate(interfaces):
        print(f"{index + 1}. {inter}")
    return interfaces


def ask_continue():
    """
    Helper function to ask the user if they want to continue and keep settings.
    Returns (repeat, keep):
        repeat: True if user wants to continue, False otherwise
        keep: True if user wants to keep settings, False if not,
        None if not continuing
    """
    while True:
        repeat = input("Wanna continue? y/n: ").strip().lower()
        if repeat == "y":
            while True:
                keep = input("Keep settings? y/n: ").strip().lower()
                if keep == "y":
                    PROTOCOL_HISTORY.append(50 * "-")
                    return True, True
                elif keep == "n":
                    return True, False
                else:
                    print("Invalid option!")
        elif repeat == "n":
            return False, None
        else:
            print("Invalid option!")


def capture_packets(interface):
    """
    Function for capturing packets
    """
    # Ask for settings only once
    while True:
        packet_count = input(
            "How many packets do you want to capture? (Enter = unlimited): "
        )
        if packet_count == "":
            packet_count = None
            break
        try:
            packet_count = int(packet_count)
            if packet_count > 0:
                break
            else:
                print("Enter a number greater than 0 or press Enter.")
        except ValueError:
            print("Enter a number or press Enter.")

    print(
        "\nEnter filter for packet capture (e.g. 'tcp', 'udp', 'port 80', "
        "'tcp and port 80', 'tcp or udp')"
    )
    print(
        "Use and, or, not, port, ip, tcp, udp, icmp...\nFor everything, "
        "press Enter."
    )

    filter_option = input("Enter filter: ")

    # Main capture loop - use the same settings until user chooses "don't keep"
    # settings"
    while True:
        sniff_kwargs = dict(iface=interface, prn=analyze_packet)

        if packet_count:
            sniff_kwargs['count'] = packet_count

        if filter_option:
            sniff_kwargs['filter'] = filter_option

        if not filter_option:
            print("No filter will be used, capturing everything.")
        else:
            print(f"Using filter: {filter_option}")

        print("Starting packet capture... (Press Ctrl+C to stop)")
        try:
            scapy.sniff(**sniff_kwargs)
            print("Packet capture completed.")
        except KeyboardInterrupt:
            print("\nPacket capture stopped by user (Ctrl+C).")
            repeat, keep = ask_continue()
            if not repeat:
                return
            if not keep:
                return capture_packets(interface)
            # else: keep settings, continue with same settings
        except PermissionError:
            os.system("cls" if os.name == "nt" else "clear")
            print("\nERROR: Permission denied!")
            print(40 * "-")
            print("Network packet capture requires administrator privileges.")
            print("--->", end='')
            print("  Please run the program as root/administrator")
            return
        except Exception as e:
            print(f"Error in filter or packet count: {e}\nTry again.")
            continue
        # If sniffing completes successfully (e.g., after packet count),
        # ask to continue
        repeat, keep = ask_continue()
        if not repeat:
            return
        if not keep:
            return capture_packets(interface)
        # else: keep settings, continue with same settings


def analyze_packet(packet):
    """
    Function for analyzing a single packet
    """
    t = f"[{time.strftime('%H:%M:%S', time.localtime())}]"
    size = len(packet)
    proto = "-"
    src_ip = dst_ip = src_port = dst_port = "-"
    osi_layer = "?"

    # ARP protocol detection
    if packet.haslayer(scapy.ARP):
        proto = "ARP"
        osi_layer = "2 (Link)"
        src_ip = packet[scapy.ARP].psrc
        dst_ip = packet[scapy.ARP].pdst

    # IPv4 protocol detection
    elif packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        osi_layer = "3 (Network)"

        # TCP over IPv4
        if packet.haslayer(scapy.TCP):
            proto = "TCP"
            osi_layer = "4 (Transport)"
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

        # UDP over IPv4
        elif packet.haslayer(scapy.UDP):
            proto = "UDP"
            osi_layer = "4 (Transport)"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport

        # ICMP over IPv4
        elif packet.haslayer(scapy.ICMP):
            proto = "ICMP"
            osi_layer = "3 (Network)"

        # Pure IPv4 packet
        else:
            proto = "IP"

    # IPv6 protocol detection
    elif packet.haslayer(scapy.IPv6):
        src_ip = packet[scapy.IPv6].src
        dst_ip = packet[scapy.IPv6].dst
        osi_layer = "3 (Network)"

        # TCP over IPv6
        if packet.haslayer(scapy.TCP):
            proto = "TCP6"
            osi_layer = "4 (Transport)"
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

        # UDP over IPv6
        elif packet.haslayer(scapy.UDP):
            proto = "UDP6"
            osi_layer = "4 (Transport)"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport

        # Pure IPv6 packet
        else:
            proto = "IPv6"

    # STP (Spanning Tree Protocol)
    elif packet.haslayer(scapy.STP):
        proto = "STP"
        osi_layer = "2 (Link)"

    # EAPOL (Extensible Authentication Protocol over LAN)
    elif packet.haslayer(scapy.EAPOL):
        proto = "EAPOL"
        osi_layer = "2 (Link)"

    # LLC (Logical Link Control)
    elif packet.haslayer(scapy.LLC):
        proto = "LLC"
        osi_layer = "2 (Link)"

    # 802.3 Ethernet frame
    elif packet.haslayer(scapy.Dot3):
        proto = "802.3"
        osi_layer = "2 (Link)"

    # Unknown/unrecognized protocol
    else:
        proto = "OTHER"
        osi_layer = "?"

    # DNS query recognition - assign output to text variable
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
        try:
            qname = packet[scapy.DNSQR].qname.decode(errors='ignore')
            if packet.haslayer(scapy.UDP):
                text = (f"{t} {Fore.RED}DNS{Style.RESET_ALL} Query "
                        f"(UDP port 53) | {src_ip} -> {dst_ip} | "
                        f"domain: {qname}")
            elif packet.haslayer(scapy.TCP):
                text = (f"{t} {Fore.RED}DNS{Style.RESET_ALL} Query "
                        f"(TCP port 53) | {src_ip} -> {dst_ip} | "
                        f"domain: {qname}")
        except Exception:
            pass

    # TLS/SSL encrypted connections - show both app and transport protocol
    elif tls_detection(packet) and (proto == "TCP" or proto == "TCP6"):
        tcp_flags = packet[scapy.TCP].flags
        payload = packet[scapy.Raw].load
        tls_type = "UNKNOWN"
        if len(payload) > 5 and payload[5] in TLS_HANDSHAKE_TYPES:
            tls_type = TLS_HANDSHAKE_TYPES[payload[5]]
        if dst_port == 443 or src_port == 443:
            text = (f"{t} {Fore.CYAN}HTTPS{Style.RESET_ALL}/"
                    f"{Fore.MAGENTA}TLS{Style.RESET_ALL} {tls_type} ("
                    f"{Fore.GREEN}{proto}{Style.RESET_ALL} {tcp_flags}) | "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                    f"Encrypted | size: {size} bytes")
            proto = "HTTPS/TLS"
        elif dst_port == 993 or src_port == 993:
            text = (f"{t} {Fore.CYAN}IMAPS{Style.RESET_ALL}/"
                    f"{Fore.MAGENTA}TLS{Style.RESET_ALL} {tls_type} ("
                    f"{Fore.GREEN}{proto}{Style.RESET_ALL} {tcp_flags}) | "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                    f"Encrypted | size: {size} bytes")
            proto = "IMAP/TLS"
        elif dst_port == 995 or src_port == 995:
            text = (f"{t} {Fore.CYAN}POP3S{Style.RESET_ALL}/"
                    f"{Fore.MAGENTA}TLS{Style.RESET_ALL} {tls_type} ("
                    f"{Fore.GREEN}{proto}{Style.RESET_ALL} {tcp_flags}) | "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                    f"Encrypted | size: {size} bytes")
            proto = "POP3S/TLS"
        else:
            text = (f"{t} {Fore.MAGENTA}TLS/SSL{Style.RESET_ALL} {tls_type} ("
                    f"{Fore.GREEN}{proto}{Style.RESET_ALL} {tcp_flags}) | "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                    f"Encrypted on port {dst_port} | "
                    f"size: {size} bytes")
            proto = "POP3S/TLS"

    # Protocol detection by port number (from dictionary)
    elif (proto == "TCP" or proto == "TCP6" or
          proto == "UDP" or proto == "UDP6"):
        proto_name = (PORT_PROTOCOLS.get(dst_port) or
                      PORT_PROTOCOLS.get(src_port))

        if proto_name:
            # Show both application protocol AND transport protocol
            if proto == "TCP" or proto == "TCP6":
                tcp_flags = packet[scapy.TCP].flags
                if proto_name == "DNS":
                    text = (f"{t} {Fore.RED}DNS{Style.RESET_ALL} ("
                            f"{Fore.GREEN}{proto}{Style.RESET_ALL} "
                            f"{tcp_flags}) | {src_ip}:{src_port} -> "
                            f"{dst_ip}:{dst_port} | size: {size} bytes")
                else:
                    text = (f"{t} {Fore.CYAN}{proto_name}{Style.RESET_ALL} ("
                            f"{Fore.GREEN}{proto}{Style.RESET_ALL} "
                            f"{tcp_flags}) | {src_ip}:{src_port} -> "
                            f"{dst_ip}:{dst_port} | size: {size} bytes")
            else:  # UDP
                if proto_name == "DNS":
                    text = (f"{t} {Fore.RED}DNS{Style.RESET_ALL} ("
                            f"{Fore.BLUE}{proto}{Style.RESET_ALL}) | "
                            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                            f"size: {size} bytes")
                else:
                    text = (f"{t} {Fore.CYAN}{proto_name}{Style.RESET_ALL} ("
                            f"{Fore.BLUE}{proto}{Style.RESET_ALL}) | "
                            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                            f"size: {size} bytes")
            proto = proto_name
        else:
            # Unknown application protocol - show transport only
            if proto == "TCP" or proto == "TCP6":
                tcp_flags = packet[scapy.TCP].flags
                text = (f"{Fore.RED}{t} UNKNOWN ({proto} {tcp_flags}) | "
                        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                        f"size: {size} bytes{Style.RESET_ALL}")
            else:  # UDP
                text = (f"{Fore.RED}{t} UNKNOWN ({proto}) | "
                        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                        f"size: {size} bytes{Style.RESET_ALL}")

    # TCP packets with flags (backup case)
    elif proto == "TCP" or proto == "TCP6":
        tcp_flags = packet[scapy.TCP].flags
        text = (f"{t} {Fore.GREEN}TCP{Style.RESET_ALL} ({tcp_flags}) | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"size: {size} bytes")

    # UDP packets (backup case)
    elif proto == "UDP" or proto == "UDP6":
        text = (f"{t} {Fore.BLUE}UDP{Style.RESET_ALL} | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"size: {size} bytes")

    # Unknown/unspecified protocols
    elif proto == "OTHER":
        text = (f"{Fore.RED}[{t}] UNSPECIFIED/UNKNOWN PROTOCOL "
                f"(could be GRE, ESP, IGMP, OSPF, etc.){Style.RESET_ALL}")

    # ARP packet details - who is asking for whom
    elif proto == "ARP":
        if packet[scapy.ARP].op == 1:  # ARP Request
            text = (f"{t} {Fore.YELLOW}ARP{Style.RESET_ALL} Request | "
                    f"Who has {dst_ip}? Tell {src_ip} | "
                    f"size: {size} bytes")
        elif packet[scapy.ARP].op == 2:  # ARP Reply
            text = (f"{t} {Fore.YELLOW}ARP{Style.RESET_ALL} Reply | "
                    f"{src_ip} is at MAC {packet[scapy.ARP].hwsrc} | "
                    f"size: {size} bytes")
        else:
            text = (f"{t} {Fore.YELLOW}ARP{Style.RESET_ALL} "
                    f"(OSI {osi_layer}) | {src_ip} -> {dst_ip} | "
                    f"size: {size} bytes")
    elif osi_layer == "2 (Link)":
        if packet.haslayer(scapy.Dot3):
            text = (
                f"{t} {Fore.BLACK}{Style.BRIGHT}{proto}{Style.RESET_ALL} "
                f"(OSI {osi_layer}) | MAC: "
                f"{packet[scapy.Dot3].src} -> {packet[scapy.Dot3].dst} | "
                f"size: {size} bytes"
            )
        elif packet.haslayer(scapy.Ether):
            text = (
                f"{t} {Fore.RED}{proto}{Style.RESET_ALL}(OSI {osi_layer}) | "
                f"MAC: {packet[scapy.Ether].src} -> "
                f"{packet[scapy.Ether].dst} | size: {size} bytes"
            )
        else:
            text = (
                f"{t} {Fore.RED}{proto}{Style.RESET_ALL} (OSI {osi_layer}) | "
                f"UNKNOWN MAC -> UNKNOWN MAC | size: {size} bytes"
            )

    # All other protocols
    else:
        text = (f"{t}{proto} (OSI {osi_layer}) | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"size: {size} bytes")
    if proto not in PROTO_STAT:
        PROTO_STAT[proto] = 1
    else:
        PROTO_STAT[proto] += 1
    print(text)
    PROTOCOL_HISTORY.append(remove_ansi_colors(text))


def choose_option(interfaces_count):
    while True:
        try:
            option = input("Choose your interface number: ")
            option = int(option)
            if 1 <= option <= interfaces_count:
                return option
            else:
                print("Invalid number. Please try again.")
        except ValueError:
            print("Please enter a valid number.")


def tls_detection(packet):
    """
    TLS/SSL detection - check for encrypted traffic
    """
    tls_detected = False
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
            tls_detected = True
    return tls_detected


def ask_save(sentence):
    save = ""
    while save != "y" and save != "n":
        save = input(sentence).lower().strip()
    return save


def remove_ansi_colors(text):
    """
    Remove ANSI color codes from text
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


if __name__ == "__main__":
    main()

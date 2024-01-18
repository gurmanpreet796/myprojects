# Import necessary modules
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
from colorama import Fore, Style
import colorama
import pyfiglet
import matplotlib.pyplot as plt
import pandas as pd
import argparse
import socket

# Set up colorama
colorama.init()

# Initialize data for reporting
packet_data = {
    'Type': [],
    'Source IP': [],
    'Destination IP': [],
    'Source Port': [],
    'Destination Port': [],
    'Packet Length': [],
    'Timestamp': [],
    'TTL': [],
    'TCP Flags': [],
    'UDP Payload Length': [],
    'UDP Payload Content': [],
    'ICMP Type': [],
    'ICMP Code': [],
    'Malware Detected': []
}

# Initialize counters
packet_count = 0
ip_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
arp_count = 0
malware_detected_count = 0

# Define the EICAR signature
EICAR_SIGNATURE = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def print_netinspector():
    custom_fig = pyfiglet.Figlet(font='slant', width=160)
    print(custom_fig.renderText('NetInspector'))


def update_data(packet, malware_detected=False):
    global packet_count, ip_count, tcp_count, udp_count, icmp_count, arp_count, malware_detected_count

    packet_count += 1

    if IP in packet:
        ip_count += 1

    if TCP in packet:
        tcp_count += 1

    if UDP in packet:
        udp_count += 1

    if ICMP in packet:
        icmp_count += 1

    if ARP in packet:
        arp_count += 1

    packet_data['Type'].append(packet.name)
    packet_data['Source IP'].append(packet[IP].src if IP in packet else None)
    packet_data['Destination IP'].append(packet[IP].dst if IP in packet else None)
    packet_data['Source Port'].append(
        packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None)
    packet_data['Destination Port'].append(
        packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None)
    packet_data['Packet Length'].append(len(packet))
    packet_data['Timestamp'].append(datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'))

    # Additional data
    if IP in packet:
        packet_data['TTL'].append(packet[IP].ttl)
    else:
        packet_data['TTL'].append(None)

    if TCP in packet:
        packet_data['TCP Flags'].append(packet[TCP].flags)

        # Check for EICAR signature in TCP payload
        tcp_payload = str(packet[TCP].payload)
        if eicar_detection(tcp_payload):
            print(colorama.Fore.LIGHTRED_EX + "EICAR signature detected in TCP payload!")
            malware_detected_count += 1
            malware_detected = True

    else:
        packet_data['TCP Flags'].append(None)

    if UDP in packet:
        packet_data['UDP Payload Length'].append(len(packet[UDP]))
        packet_data['UDP Payload Content'].append(str(packet[UDP].payload))

        # Check for EICAR signature in UDP payload
        udp_payload = str(packet[UDP].payload)
        if eicar_detection(udp_payload):
            print(colorama.Fore.LIGHTRED_EX + "EICAR signature detected in UDP payload!")
            malware_detected_count += 1
            malware_detected = True

    else:
        packet_data['UDP Payload Length'].append(None)
        packet_data['UDP Payload Content'].append(None)

    if ICMP in packet:
        packet_data['ICMP Type'].append(packet[ICMP].type)
        packet_data['ICMP Code'].append(packet[ICMP].code)
    else:
        packet_data['ICMP Type'].append(None)
        packet_data['ICMP Code'].append(None)

    packet_data['Malware Detected'].append(malware_detected)


def eicar_detection(payload):
    """Check if the payload contains the EICAR signature."""
    if isinstance(payload, bytes):
        payload_str = payload.decode(errors='ignore')
    elif isinstance(payload, str):
        payload_str = payload
    else:
        return False

    print(f"Payload (string): {payload_str}")

    if EICAR_SIGNATURE.decode() in payload_str:
        return True

    return False


def generate_report():
    df = pd.DataFrame(packet_data)
    df.to_csv('netinspector_report.csv', index=False)


def visualize_data():
    # Generate a pie chart for packet types that were actually sniffed
    labels = []
    sizes = []

    if ip_count > 0:
        labels.append('IP')
        sizes.append(ip_count)

    if tcp_count > 0:
        labels.append('TCP')
        sizes.append(tcp_count)

    if udp_count > 0:
        labels.append('UDP')
        sizes.append(udp_count)

    if icmp_count > 0:
        labels.append('ICMP')
        sizes.append(icmp_count)

    if arp_count > 0:
        labels.append('ARP')
        sizes.append(arp_count)

    # Dynamically generate explode list
    explode = [0.1 if label == 'TCP' else 0 for label in labels]

    # Create a pie chart with percentage labels inside each slice
    plt.figure(figsize=(10, 6))
    wedges, texts, autotexts = plt.pie(
        sizes,
        labels=labels,
        autopct=lambda p: f'{p:.1f}%\n({int(p * sum(sizes) / 100)})',
        startangle=140,
        explode=explode,
        wedgeprops=dict(width=0.4, edgecolor='w')
    )

    plt.title('Packet Types Distribution')

    # Display the percentage and number of packets inside each slice
    plt.gca().set_aspect('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    # Add a summary text
    summary_text = f"Total packets: {sum(sizes)}\nUnique packet types: {len(labels)}"
    plt.gcf().text(0.85, 0.5, summary_text, fontsize=12, ha='left', va='center', color='darkblue')

    # Add malware scanning information
    malware_percent = malware_detected_count / packet_count * 100 if packet_count > 0 else 0
    malware_summary = f"Malware Detected: {malware_detected_count} packets ({malware_percent:.2f}%)"
    plt.gcf().text(0.85, 0.4, malware_summary, fontsize=12, ha='left', va='center', color='darkred')

    # Save the pie chart with a custom filename
    plt.savefig('Sniffing_Report.png')

    # Display the pie chart
    plt.show()


def print_packet(packet):
    """Prints a packet with styling."""
    global malware_detected_count
    try:
        malware_detected = False
        update_data(packet)

        print(colorama.Fore.LIGHTWHITE_EX + "=" * 60)
        print(colorama.Fore.LIGHTCYAN_EX + f"Packet Type: {packet.name}")

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(colorama.Fore.LIGHTGREEN_EX + f"Source IP: {ip_src}")
            print(colorama.Fore.LIGHTGREEN_EX + f"Destination IP: {ip_dst}")

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(colorama.Fore.LIGHTBLUE_EX + f"Source Port: {sport}")
            print(colorama.Fore.LIGHTBLUE_EX + f"Destination Port: {dport}")

            # Display TCP flags
            flags = packet[TCP].flags
            print(colorama.Fore.LIGHTWHITE_EX + f"TCP Flags: {flags}")

            # Display TCP payload content as hexadecimal
            tcp_payload = bytes(packet[TCP].payload)
            print(colorama.Fore.LIGHTWHITE_EX + f"TCP Payload Content (Hex): {tcp_payload.hex()}")

            # Check for EICAR signature in TCP payload
            if eicar_detection(tcp_payload):
                print(colorama.Fore.LIGHTRED_EX + "EICAR signature detected in TCP payload!")
                malware_detected = True

        if ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(colorama.Fore.LIGHTYELLOW_EX + f"ICMP Type: {icmp_type}")
            print(colorama.Fore.LIGHTYELLOW_EX + f"ICMP Code: {icmp_code}")

            # Display ICMP payload content as bytes
            icmp_payload = packet[ICMP].payload
            print(colorama.Fore.LIGHTWHITE_EX + f"ICMP Payload Content: {icmp_payload}")

        if ARP in packet:
            arp_op = packet[ARP].op
            arp_src_ip = packet[ARP].psrc
            arp_dst_ip = packet[ARP].pdst
            print(colorama.Fore.LIGHTRED_EX + f"ARP Operation: {arp_op}")
            print(colorama.Fore.LIGHTRED_EX + f"Source IP: {arp_src_ip}")
            print(colorama.Fore.LIGHTRED_EX + f"Destination IP: {arp_dst_ip}")

        # Display packet length
        print(colorama.Fore.LIGHTWHITE_EX + f"Packet Length: {len(packet)} bytes")

        # Display timestamp
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
        print(colorama.Fore.LIGHTWHITE_EX + f"Timestamp: {timestamp}")

        # Display TTL (if applicable)
        if IP in packet:
            ttl = packet[IP].ttl
            print(colorama.Fore.LIGHTWHITE_EX + f"TTL: {ttl}")

        # Display TCP flags (if applicable)
        if TCP in packet:
            flags = packet[TCP].flags
            print(colorama.Fore.LIGHTWHITE_EX + f"TCP Flags: {flags}")

        # Display UDP payload length and content (if applicable)
        if UDP in packet:
            payload_len = len(packet[UDP])
            payload = packet[UDP].payload
            print(colorama.Fore.LIGHTWHITE_EX + f"UDP Payload Length: {payload_len} bytes")
            print(colorama.Fore.LIGHTWHITE_EX + f"UDP Payload Content: {payload}")

        # Display ICMP type and code (if applicable)
        if ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(colorama.Fore.LIGHTWHITE_EX + f"ICMP Type: {icmp_type}")
            print(colorama.Fore.LIGHTWHITE_EX + f"ICMP Code: {icmp_code}")

        # Display malware detection status
        if malware_detected:
            malware_detected_count += 1
            packet_data['Malware Detected'][-1] = True

    except Exception as e:
        print(f"An error occurred while processing a packet: {e}")


def packet_callback(packet):
    global malware_detected_count
    malware_detected = False
    update_data(packet)

    print(colorama.Fore.LIGHTWHITE_EX + "=" * 60)
    print(colorama.Fore.LIGHTCYAN_EX + f"Packet Type: {packet.name}")

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(colorama.Fore.LIGHTGREEN_EX + f"Source IP: {ip_src}")
        print(colorama.Fore.LIGHTGREEN_EX + f"Destination IP: {ip_dst}")

    # ... (rest of the function remains unchanged)

    # Perform EICAR signature detection on TCP payload
    if TCP in packet:
        tcp_payload = bytes(packet[TCP].payload)
        if eicar_detection(tcp_payload):
            print(colorama.Fore.LIGHTRED_EX + "EICAR signature detected in TCP payload!")
            malware_detected = True

    # Print other packet details as before
    print_packet(packet)

    # Update malware detection status
    if malware_detected:
        malware_detected_count += 1
        packet_data['Malware Detected'][-1] = True


def main():
    """Sniffs specific packets on the network and prints them out with detailed information."""

    parser = argparse.ArgumentParser(description='NetInspector - A network packet sniffer.')
    parser.add_argument('-s', '--source-ip', help='Filter packets based on source IP address.')
    parser.add_argument('-p', '--port', type=int, help='Filter packets based on destination port.')
    parser.add_argument('--udp', action='store_true', help='Capture only UDP packets.')
    parser.add_argument('--tcp', action='store_true', help='Capture only TCP packets.')
    parser.add_argument('--icmp', action='store_true', help='Capture only ICMP packets.')
    parser.add_argument('--arp', action='store_true', help='Capture only ARP packets.')

    args = parser.parse_args()

    try:
        # Start sniffing the network with optional filters
        print_netinspector()
        filter_expression = ""

        if args.source_ip:
            filter_expression += f" and host {args.source_ip}"

        if args.port:
            filter_expression += f" and port {args.port}"

        if args.udp:
            filter_expression += " and udp"

        if args.tcp:
            filter_expression += " and tcp"

        if args.icmp:
            filter_expression += " and icmp"

        if args.arp:
            filter_expression += " and arp"

        if filter_expression.startswith(" and"):
            filter_expression = filter_expression[4:]

        if filter_expression:
            sniff(prn=packet_callback, filter=filter_expression, store=0)
        else:
            sniff(prn=packet_callback, store=0)

        visualize_data()
        generate_report()
    except KeyboardInterrupt:
        print("Sniffing stopped.")
        visualize_data()
        generate_report()
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
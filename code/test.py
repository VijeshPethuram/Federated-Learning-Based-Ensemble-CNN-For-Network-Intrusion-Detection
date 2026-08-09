import time
from scapy.all import *

def send_test_packets():
    # Duration (send packets with delay)
    for i in range(5):
        packet = IP(dst="127.0.0.1") / TCP(dport=5550, flags="S") / "Custom Payload"
        print(f"Sending packet with delay to {packet[IP].dst} on port {packet[TCP].dport}:")
        packet.show()
        send(packet)
        time.sleep(1)  # 1 second delay

    # Protocol types
    tcp_packet = IP(dst="127.0.0.1") / TCP(dport=5550)
    udp_packet = IP(dst="127.0.0.1") / UDP(dport=5550)
    icmp_packet = IP(dst="127.0.0.1") / ICMP()
    print(f"Sending TCP packet to {tcp_packet[IP].dst} on port {tcp_packet[TCP].dport}:")
    tcp_packet.show()
    send(tcp_packet)
    print(f"Sending UDP packet to {udp_packet[IP].dst} on port {udp_packet[UDP].dport}:")
    udp_packet.show()
    send(udp_packet)
    print(f"Sending ICMP packet to {icmp_packet[IP].dst}:")
    icmp_packet.show()
    send(icmp_packet)

    # Services (ports)
    http_packet = IP(dst="127.0.0.1") / TCP(dport=5550)
    dns_packet = IP(dst="127.0.0.1") / UDP(dport=5550)
    print(f"Sending HTTP packet to {http_packet[IP].dst} on port {http_packet[TCP].dport}:")
    http_packet.show()
    send(http_packet)
    print(f"Sending DNS packet to {dns_packet[IP].dst} on port {dns_packet[UDP].dport}:")
    dns_packet.show()
    send(dns_packet)

    # TCP Flags
    syn_packet = IP(dst="127.0.0.1") / TCP(dport=5550, flags="S")
    ack_packet = IP(dst="127.0.0.1") / TCP(dport=5550, flags="A")
    print(f"Sending SYN packet to {syn_packet[IP].dst} on port {syn_packet[TCP].dport}:")
    syn_packet.show()
    send(syn_packet)
    print(f"Sending ACK packet to {ack_packet[IP].dst} on port {ack_packet[TCP].dport}:")
    ack_packet.show()
    send(ack_packet)

    # Src Bytes and Dst Bytes
    small_packet = IP(dst="127.0.0.1") / TCP(dport=5550) / "Small"
    large_packet = IP(dst="127.0.0.1") / TCP(dport=5550) / ("Large" * 100)
    print(f"Sending small packet to {small_packet[IP].dst} on port {small_packet[TCP].dport}:")
    small_packet.show()
    send(small_packet)
    print(f"Sending large packet to {large_packet[IP].dst} on port {large_packet[TCP].dport}:")
    large_packet.show()
    send(large_packet)

    # Land attack
    land_packet = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=5550)
    print(f"Sending land attack packet to {land_packet[IP].dst} on port {land_packet[TCP].dport}:")
    land_packet.show()
    send(land_packet)

    # Wrong Fragment
    frag_packet = IP(dst="127.0.0.1", flags="MF", frag=0) / TCP(dport=5550) / "Fragmented"
    print(f"Sending fragmented packet to {frag_packet[IP].dst} on port {frag_packet[TCP].dport}:")
    frag_packet.show()
    send(frag_packet)

    # Urgent
    urgent_packet = IP(dst="127.0.0.1") / TCP(dport=5550, urgptr=1) / "Urgent"
    print(f"Sending urgent packet to {urgent_packet[IP].dst} on port {urgent_packet[TCP].dport}:")
    urgent_packet.show()
    send(urgent_packet)

    # Hot connections
    for i in range(15):
        hot_packet = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=5550)
        print(f"Sending hot connection packet {i+1} to {hot_packet[IP].dst} on port {hot_packet[TCP].dport}:")
        hot_packet.show()
        send(hot_packet)

    # Error Rates
    rst_packet = IP(dst="127.0.0.1") / TCP(dport=5550, flags="R")
    syn_rst_packet = IP(dst="127.0.0.1") / TCP(dport=5550, flags="SR")
    print(f"Sending RST packet to {rst_packet[IP].dst} on port {rst_packet[TCP].dport}:")
    rst_packet.show()
    send(rst_packet)
    print(f"Sending SYN+RST packet to {syn_rst_packet[IP].dst} on port {syn_rst_packet[TCP].dport}:")
    syn_rst_packet.show()
    send(syn_rst_packet)

# Run the function to send test packets
send_test_packets()
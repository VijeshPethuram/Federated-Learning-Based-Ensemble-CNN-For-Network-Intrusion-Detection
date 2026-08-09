from scapy.all import *
import pandas as pd
from collections import defaultdict
import requests

ML_SERVER_URL = "http://localhost:5000/predict"  

features_list = []
sessions = defaultdict(list)

def extract_features(packet):
    if IP in packet and TCP in packet:
        session_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
        sessions[session_key].append(packet)

def compute_session_features(session_packets):
    features = {}
    
    features['protocol_type'] = session_packets[0][IP].proto
    features['flag'] = str(session_packets[0][TCP].flags)  
    features['land'] = int(session_packets[0][IP].src == session_packets[0][IP].dst and
                           session_packets[0][TCP].sport == session_packets[0][TCP].dport)
    
    features['duration'] = session_packets[-1].time - session_packets[0].time

    src_bytes = 0
    dst_bytes = 0

    for packet in session_packets:
        if packet[IP].src == session_packets[-1][IP].src:
            src_bytes += len(packet)
        if packet[IP].dst == session_packets[-1][IP].dst:
            dst_bytes += len(packet)

    # Assign the calculated byte counts to features
    features['src_bytes'] = src_bytes
    features['dst_bytes'] = dst_bytes

    # Calculate the number of wrong fragments
    wrong_fragment_count = 0
    for packet in session_packets:
        if packet.haslayer(IP) and packet[IP].flags == 1:
            wrong_fragment_count += 1
    features['wrong_fragment'] = wrong_fragment_count

    # Check for urgent packets
    urgent_count = 0
    for packet in session_packets:
        if packet.haslayer(TCP) and hasattr(packet[TCP], 'urg') and packet[TCP].urg:
            urgent_count += 1
    features['urgent'] = int(urgent_count > 0)

    # Count unique source IPs
    unique_src_ips = set()
    for packet in session_packets:
        unique_src_ips.add(packet[IP].src)
    features['hot'] = len(unique_src_ips)

    # Count total packets in the session
    features['srv_count'] = len(session_packets)

    # Calculate error rates
    serror_count = sum(1 for p in session_packets if p.haslayer(TCP) and p[TCP].flags & 0x04)
    features['serror_rate'] = serror_count / len(session_packets) if session_packets else 0
    features['srv_serror_rate'] = features['serror_rate']  

    rerror_count = sum(1 for p in session_packets if p.haslayer(TCP) and p[TCP].flags & 0x01)
    features['rerror_rate'] = rerror_count / len(session_packets) if session_packets else 0
    features['srv_rerror_rate'] = features['rerror_rate'] 

    # Calculate service counts
    same_srv_count = len(set(p[TCP].dport for p in session_packets))
    diff_srv_count = len(set(p[IP].dst for p in session_packets))
    
    features['same_srv_rate'] = same_srv_count / len(session_packets) if session_packets else 0
    features['diff_srv_rate'] = diff_srv_count / len(session_packets) if session_packets else 0
    
    # Host-related features
    features['dst_host_count'] = len(set(p[IP].dst for p in session_packets))
    features['dst_host_srv_count'] = len(set((p[IP].dst, p[TCP].dport) for p in session_packets))
    
    # Calculate rates for destination hosts
    same_srv_rate_count = sum(1 for p in session_packets if p[TCP].dport == session_packets[0][TCP].dport)
    features['dst_host_same_srv_rate'] = same_srv_rate_count / len(session_packets) if session_packets else 0

    diff_srv_rate_count = len(set(p[TCP].dport for p in session_packets))
    features['dst_host_diff_srv_rate'] = diff_srv_rate_count / len(session_packets) if session_packets else 0

    same_src_port_count = len(set(p[TCP].sport for p in session_packets))
    features['dst_host_same_src_port_rate'] = same_src_port_count / len(session_packets) if session_packets else 0
    
    # Error rates for destination hosts
    dst_host_serror_count = sum(1 for p in session_packets if p.haslayer(TCP) and p[TCP].flags & 0x04)
    features['dst_host_serror_rate'] = dst_host_serror_count / len(session_packets) if session_packets else 0

    dst_host_srv_serror_count = sum(1 for p in session_packets if p.haslayer(TCP) and p[TCP].flags & 0x04 and p[TCP].dport == session_packets[0][TCP].dport)
    features['dst_host_srv_serror_rate'] = dst_host_srv_serror_count / len(session_packets) if session_packets else 0

    dst_host_rerror_count = sum(1 for p in session_packets if p.haslayer(TCP) and p[TCP].flags & 0x01)
    features['dst_host_rerror_rate'] = dst_host_rerror_count / len(session_packets) if session_packets else 0

    dst_host_srv_rerror_count = sum(1 for p in session_packets if p.haslayer(TCP) and p[TCP].flags & 0x01 and p[TCP].dport == session_packets[0][TCP].dport)
    features['dst_host_srv_rerror_rate'] = dst_host_srv_rerror_count / len(session_packets) if session_packets else 0
    
    return features

def send_to_ml_server(features):
    """Send the extracted features to the machine learning server."""
    try:
        response = requests.post(ML_SERVER_URL, json=features)
        if response.status_code == 200:
            print(f"Response from ML Server: {response.json()}")
        else:
            print(f"Failed to get response from ML Server, Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending data to ML server: {e}")

def packet_callback(packet):
    """Callback function for processing each captured packet ."""
    extract_features(packet)
    # Process each session and compute features
    for session_key, session_packets in list(sessions.items()):  # Use list to avoid modifying dict during iteration
        if len(session_packets) > 1:  # Only process sessions with more than one packet
            features = compute_session_features(session_packets)
            features_list.append(features)
            send_to_ml_server(features) 
            # Optionally clear the session after processing
            del sessions[session_key]

print("Starting packet capture on interface:")
# Start capturing TCP packets and process them with the packet_callback function
sniff(prn=packet_callback, store=0, filter="tcp and port 3000")

print("Stopping packet capture...")
# Save the collected features to a CSV file
pd.DataFrame(features_list).to_csv('packet_features.csv', index=False)
print("Packet features saved to packet_features.csv")
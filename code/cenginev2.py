from scapy.all import *
import pandas as pd
from collections import defaultdict
import time
import requests

ML_SERVER_URL = "http://localhost:5000/predict"  

features_list = []

sessions = defaultdict(list)

def extract_features(packet):
    if IP in packet and TCP in packet:
        session_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
        
        sessions[session_key].append(packet)

def compute_session_features(sessionpackt):
    features = {}
    
    features['protocol_type'] = sessionpackt[0][IP].proto
    features['flag'] = str(sessionpackt[0][TCP].flag)  
    features['land'] = int(sessionpackt[0][IP].src == sessionpackt[0][IP].dst and
                           sessionpackt[0][TCP].sport == sessionpackt[0][TCP].dport)
    
    features['duration'] = sessionpackt[-1].time - sessionpackt[0].time  
    features['src_bytes'] = sum(len(p) for p in sessionpackt if p[IP].src == sessionpackt[-1][IP].src)
    features['dst_bytes'] = sum(len(p) for p in sessionpackt if p[IP].dst == sessionpackt[-1][IP].dst)
    
    features['wrong_fragment'] = sum(1 for p in sessionpackt if p.haslayer(IP) and p[IP].flags == 1) 
    
    features['urgent'] = int(any(p.haslayer(TCP) and hasattr(p[TCP], 'urg') and p[TCP].urg for p in sessionpackt))
    
    features['hot'] = len(set(p[IP].src for p in sessionpackt)) 
    
    features['srv_count'] = len(sessionpackt)
    
    features['serror_rate'] = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x04) / len(sessionpackt) if sessionpackt else 0
    features['srv_serror_rate'] = features['serror_rate']  
    features['rerror_rate'] = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x01) / len(sessionpackt) if sessionpackt else 0
    features['srv_rerror_rate'] = features['rerror_rate'] 
    
    same_srv_count = len(set(p[TCP].dport for p in sessionpackt))
    diff_srv_count = len(set(p[IP].dst for p in sessionpackt))
    
    features['same_srv_rate'] = same_srv_count / len(sessionpackt) if sessionpackt else 0
    features['diff_srv_rate'] = diff_srv_count / len(sessionpackt) if sessionpackt else 0
    
    features['dst_host_count'] = len(set(p[IP].dst for p in sessionpackt))
    features['dst_host_srv_count'] = len(set((p[IP].dst, p[TCP].dport) for p in sessionpackt))
    
    features['dst_host_same_srv_rate'] = sum(1 for p in sessionpackt if p[TCP].dport == sessionpackt[0][TCP].dport) / len(sessionpackt) if sessionpackt else 0
    features['dst_host_diff_srv_rate'] = len(set(p[TCP].dport for p in sessionpackt)) / len(sessionpackt) if sessionpackt else 0
    features['dst_host_same_src_port_rate'] = len(set(p[TCP].sport for p in sessionpackt)) / len(sessionpackt) if sessionpackt else 0
    
    features['dst_host_serror_rate'] = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x04) / len(sessionpackt) if sessionpackt else 0
    features['dst_host_srv_serror_rate'] = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x04 and p[TCP].dport == sessionpackt[0][TCP].dport) / len(sessionpackt) if sessionpackt else 0
    features['dst_host_rerror_rate'] = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x01) / len(sessionpackt) if sessionpackt else 0
    features['dst_host_srv_rerror_rate'] = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x01 and p[TCP].dport == sessionpackt[0][TCP].dport) / len(sessionpackt) if sessionpackt else 0
    
    return features

def send_to_ml_server(features):
    try:
        response = requests.post(ML_SERVER_URL, json=features)
        if response.status_code == 200:
            print(f"Response from ML Server: {response.json()}")
        else:
            print(f"Failed to get response from ML Server, Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending data to ML server: {e}")

def packet_callback(packet):
    extract_features(packet)
    if len(sessions) > 0:
        for session_key, sessionpackt in sessions.items():
            if len(sessionpackt) > 1: 
                features = compute_session_features(sessionpackt)
                features_list.append(features)
                send_to_ml_server(features) 

print("Starting packet capture on interface:")
sniff(prn=packet_callback, store=0, filter="tcp")

print("Stopping packet capture...")
pd.DataFrame(features_list).to_csv('packet_features.csv', index=False)
print("Packet features saved to packet_features.csv")




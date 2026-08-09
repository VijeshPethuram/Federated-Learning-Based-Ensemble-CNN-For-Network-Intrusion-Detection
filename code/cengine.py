from scapy.all import *
import pandas as pd
import requests
import secrets
import hashlib
import hmac
from collections import defaultdict

# Configuration
TRA_URL = "http://localhost:6000"
ML_SERVER_URL = "http://localhost:5000/predict"
ENTITY_ID = "capture_engine_1"
SESSION_KEY = None

# Registration with TRA
def register_with_tra():
    global SESSION_KEY
    response = requests.post(
        f"{TRA_URL}/register",
        json={"entity_id": ENTITY_ID, "entity_type": "capture_engine"}
    )
    if response.status_code == 201:
        SESSION_KEY = response.json()["session_key"]
        print("Successfully registered with TRA. SKEY:", SESSION_KEY)
    else:
        raise Exception("TRA registration failed")

# Generate authentication headers
def generate_auth_headers():
    nonce = secrets.token_hex(16)
    hmac_val = hmac.new(
        bytes.fromhex(SESSION_KEY), 
        nonce.encode(), 
        hashlib.sha256
    ).hexdigest()
    return {
        "Entity-ID": ENTITY_ID,
        "Nonce": nonce,
        "HMAC": hmac_val
    }



# 🔹 **Packet Capture and Feature Extraction** (No Changes)
featureslist = []
sessions = defaultdict(list)

protocol_map = {6: "tcp", 17: "udp", 1: "icmp"}  
service_mapping = {
    80: "http", 21: "ftp", 23: "telnet", 25: "smtp", 443: "https", 22: "ssh", 
    53: "dns", 110: "pop3", 995: "pop3s", 143: "imap", 993: "imaps", 161: "snmp",
    3306: "mysql", 5432: "postgresql", 8080: "http_alt"
}

def extractfeatures(packet):
    if IP in packet and TCP in packet:
        sessionkey = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
        sessions[sessionkey].append(packet)

def computesessionfeatures(sessionpackt):
    features = {}

    # Ensure correct protocol naming
    features["protocol_type"] = protocol_map.get(sessionpackt[0][IP].proto, "other")
    features["service"] = str(sessionpackt[0][TCP].dport)
    features["service"] = pd.Series([features["service"]]).map(service_mapping).fillna("other").iloc[0]
    features["flag"] = str(sessionpackt[0][TCP].flags)

    features["duration"] = sessionpackt[-1].time - sessionpackt[0].time
    features["land"] = int(sessionpackt[0][IP].src == sessionpackt[0][IP].dst and sessionpackt[0][TCP].sport == sessionpackt[0][TCP].dport)

    srcbytes = sum(len(p) for p in sessionpackt if p[IP].src == sessionpackt[0][IP].src)
    dstbytes = sum(len(p) for p in sessionpackt if p[IP].dst == sessionpackt[0][IP].dst)
    wrong_fragment = sum(1 for p in sessionpackt if p.haslayer(IP) and p[IP].flags == 1)
    urgent = any(p.haslayer(TCP) and getattr(p[TCP], 'urg', 0) for p in sessionpackt)

    serror_count = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x04)
    rerror_count = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x01)
    
    hot = len(set(p[IP].src for p in sessionpackt))
    srv_count = len(sessionpackt)

    diffsrvcount = set(p[IP].dst for p in sessionpackt)

    # Rates
    features["src_bytes"] = srcbytes
    features["dst_bytes"] = dstbytes
    features["wrong_fragment"] = wrong_fragment
    features["urgent"] = int(urgent)
    features["hot"] = hot
    features["srv_count"] = srv_count
    features["serror_rate"] = serror_count / srv_count if srv_count > 0 else 0
    features["srv_serror_rate"] = features["serror_rate"]
    features["rerror_rate"] = rerror_count / srv_count if srv_count > 0 else 0
    features["srv_rerror_rate"] = features["rerror_rate"]
    features["same_srv_rate"] = len(set(p[TCP].dport for p in sessionpackt)) / srv_count if srv_count > 0 else 0
    features["diff_srv_rate"] = len(diffsrvcount) / srv_count if srv_count > 0 else 0
    features["srv_diff_host_rate"] = len(set(p[IP].src for p in sessionpackt)) / srv_count if srv_count > 0 else 0

    features["dst_host_count"] = len(diffsrvcount)
    features["dst_host_srv_count"] = len(set((p[IP].dst, p[TCP].dport) for p in sessionpackt))

    dst_host_same_srv_rate = sum(1 for p in sessionpackt if p[TCP].dport == sessionpackt[0][TCP].dport) / srv_count if srv_count > 0 else 0
    dst_host_diff_srv_rate = len(set(p[TCP].dport for p in sessionpackt)) / srv_count if srv_count > 0 else 0
    dst_host_same_src_port_rate = sum(1 for p in sessionpackt if p[TCP].sport == sessionpackt[0][TCP].sport) / srv_count if srv_count > 0 else 0

    dst_host_serror_rate = serror_count / srv_count if srv_count > 0 else 0
    dst_host_srv_serror_rate = dst_host_serror_rate
    dst_host_rerror_rate = rerror_count / srv_count if srv_count > 0 else 0
    dst_host_srv_rerror_rate = dst_host_rerror_rate

    features["dst_host_same_srv_rate"] = dst_host_same_srv_rate
    features["dst_host_diff_srv_rate"] = dst_host_diff_srv_rate
    features["dst_host_same_src_port_rate"] = dst_host_same_src_port_rate
    

    features["dst_host_srv_diff_host_rate"] = len(set(p[IP].src for p in sessionpackt)) / srv_count if srv_count > 0 else 0

    features["dst_host_serror_rate"] = dst_host_serror_rate
    features["dst_host_srv_serror_rate"] = dst_host_srv_serror_rate
    features["dst_host_rerror_rate"] = dst_host_rerror_rate
    features["dst_host_srv_rerror_rate"] = dst_host_srv_rerror_rate
    return features

def packetcallback(packet):
    extractfeatures(packet)
    if len(sessions) > 0:
        for sessionkey in list(sessions.keys()):
            sessionpackt = sessions[sessionkey]
            if len(sessionpackt) > 1: 
                features = computesessionfeatures(sessionpackt)
                dataset_columns = [
                   "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
                    "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate",
                    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
                    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
                ]
                ordered_features = {col: features.get(col, 0) for col in dataset_columns}
                featureslist.append(ordered_features)
                sendtoserver(ordered_features)



def sendtoserver(features):
    try:
        headers = generate_auth_headers()
        response = requests.post(
            ML_SERVER_URL,
            json=features,
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            print("Packet received. Prediction from Cloud server: ",result)
            if result.get("prediction") == "anomaly":
                requests.post("http://localhost:5550/error")
    except Exception as e:
        print(f"Communication error: {e}")

register_with_tra()
print("Starting packet capture...")
sniff(prn=packetcallback, store=0, filter="tcp and port 5550")


print("📁 Saving Captured Packet Features...")
pd.DataFrame(featureslist).to_csv('packet_features.csv', index=False)
print("✅ Packet Features Saved to packet_features.csv")

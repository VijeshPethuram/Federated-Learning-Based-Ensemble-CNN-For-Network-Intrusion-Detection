
from scapy.all import *
import pandas as pd
import requests
import secrets
import hashlib
import hmac
from collections import defaultdict

tra_url = "http://localhost:6000"
ml_server_url = "http://localhost:5000/predict"
entity_id = "capture_engine_1"
session_key = None

def registerwithtra():
    global session_key
    response = requests.post(
        f"{tra_url}/register",
        json={"entity_id": entity_id, "entity_type": "capture_engine"}
    )
    if response.status_code == 201:
        session_key = response.json()["session_key"]
        print("Successfully registered with TRA. SKEY:", session_key)
    else:
        raise Exception("TRA registration failed")

def generateauthheaders():
    nonce = secrets.token_hex(16)
    hmacval = hmac.new(
        bytes.fromhex(session_key), 
        nonce.encode(), 
        hashlib.sha256
    ).hexdigest()
    return {
        "Entity-ID": entity_id,
        "Nonce": nonce,
        "HMAC": hmacval
    }

featureslist = []
sessions = defaultdict(list)

protocolmap = {6: "tcp", 17: "udp", 1: "icmp"}  
servicemapping = {
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

    features["protocol_type"] = protocolmap.get(sessionpackt[0][IP].proto, "other")
    features["service"] = str(sessionpackt[0][TCP].dport)
    features["service"] = pd.Series([features["service"]]).map(servicemapping).fillna("other").iloc[0]
    features["flag"] = str(sessionpackt[0][TCP].flags)

    features["duration"] = sessionpackt[-1].time - sessionpackt[0].time
    features["land"] = int(sessionpackt[0][IP].src == sessionpackt[0][IP].dst and sessionpackt[0][TCP].sport == sessionpackt[0][TCP].dport)

    srcbytes = sum(len(p) for p in sessionpackt if p[IP].src == sessionpackt[0][IP].src)
    dstbytes = sum(len(p) for p in sessionpackt if p[IP].dst == sessionpackt[0][IP].dst)
    wrongfragment = sum(1 for p in sessionpackt if p.haslayer(IP) and p[IP].flags == 1)
    urgent = any(p.haslayer(TCP) and getattr(p[TCP], 'urg', 0) for p in sessionpackt)

    serrorcount = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x04)
    rerrorcount = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x01)
    
    hot = len(set(p[IP].src for p in sessionpackt))
    srvcount = len(sessionpackt)

    diffsrvcount = set(p[IP].dst for p in sessionpackt)

    features["src_bytes"] = srcbytes
    features["dst_bytes"] = dstbytes
    features["wrong_fragment"] = wrongfragment
    features["urgent"] = int(urgent)
    features["hot"] = hot
    features["srv_count"] = srvcount
    features["serror_rate"] = serrorcount / srvcount if srvcount > 0 else 0
    features["srv_serror_rate"] = features["serror_rate"]
    features["rerror_rate"] = rerrorcount / srvcount if srvcount > 0 else 0
    features["srv_rerror_rate"] = features["rerror_rate"]
    features["same_srv_rate"] = len(set(p[TCP].dport for p in sessionpackt)) / srvcount if srvcount > 0 else 0
    features["diff_srv_rate"] = len(diffsrvcount) / srvcount if srvcount > 0 else 0
    features["srv_diff_host_rate"] = len(set(p[IP].src for p in sessionpackt)) / srvcount if srvcount > 0 else 0

    features["dst_host_count"] = len(diffsrvcount)
    features["dst_host_srv_count"] = len(set((p[IP].dst, p[TCP].dport) for p in sessionpackt))

    dsthostsame_srvrate = sum(1 for p in sessionpackt if p[TCP].dport == sessionpackt[0][TCP].dport) / srvcount if srvcount > 0 else 0
    dsthostdiff_srvrate = len(set(p[TCP].dport for p in sessionpackt)) / srvcount if srvcount > 0 else 0
    dsthostsame_srcportrate = sum(1 for p in sessionpackt if p[TCP].sport == sessionpackt[0][TCP].sport) / srvcount if srvcount > 0 else 0

    dsthostserrorrate = serrorcount / srvcount if srvcount > 0 else 0
    dsthostsrvserrorrate = dsthostserrorrate
    dsthostrerrorrate = rerrorcount / srvcount if srvcount > 0 else 0
    dsthostsrvrerrorrate = dsthostrerrorrate

    features["dst_host_same_srv_rate"] = dsthostsame_srvrate
    features["dst_host_diff_srv_rate"] = dsthostdiff_srvrate
    features["dst_host_same_src_port_rate"] = dsthostsame_srcportrate
    features["dst_host_srv_diff_host_rate"] = len(set(p[IP].src for p in sessionpackt)) / srvcount if srvcount > 0 else 0

    features["dst_host_serror_rate"] = dsthostserrorrate
    features["dst_host_srv_serror_rate"] = dsthostsrvserrorrate
    features["dst_host_rerror_rate"] = dsthostrerrorrate
    features["dst_host_srv_rerror_rate"] = dsthostsrvrerrorrate
    return features

def packetcallback(packet):
    extractfeatures(packet)
    if len(sessions) > 0:
        for sessionkey in list(sessions.keys()):
            sessionpackt = sessions[sessionkey]
            if len(sessionpackt) > 1: 
                features = computesessionfeatures(sessionpackt)
                datasetcolumns = [
                   "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
                    "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate",
                    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
                    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
                ]
                orderedfeatures = {col: features.get(col, 0) for col in datasetcolumns}
                featureslist.append(orderedfeatures)
                sendtoserver(orderedfeatures)

def sendtoserver(features):
    try:
        headers = generateauthheaders()
        response = requests.post(
            ml_server_url,
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

registerwithtra()
print("Starting packet capture...")
sniff(prn=packetcallback, store=0, filter="tcp and port 5550")

print("📁 Saving Captured Packet Features...")
pd.DataFrame(featureslist).to_csv('packet_features.csv', index=False)
print("✅ Packet Features Saved to packet_features.csv")

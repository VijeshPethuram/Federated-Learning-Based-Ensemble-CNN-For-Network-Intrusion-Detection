import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time

ML_SERVER_URL = "http://localhost:5000/predict"  

class PacketCaptureEngine:
    def __init__(self):
        self.packet_count = 0  
        self.serv_count = 0  
        self.srv_count=0
        self.src_port_count = defaultdict(int)  
        self.dst_host_count = defaultdict(int)  
        self.service_count = defaultdict(int)  
        self.serror_count = 0  
        self.rerror_count = 0  
        self.connections = {}  

        
        self.last_update_time = time.time()
        self.time_limit = 60  
        
    def extract_features(self, packet):
        
        features = {
            "duration": 0,  
            "protocol_type": "",  
            "service": "",  
            "flag":"SF",
             "land": "0", 
            "src_bytes": len(packet),  
            "dst_bytes": 0, 
       
            "wrong_fragment": 0, 
            "urgent": 0,  
            "hot": 0,  
            "srv_count": self.get_srv_count(packet),  
            "serror_rate": self.get_serror_rate(),  
            "srv_serror_rate": self.get_srv_serror_rate(), 
            "rerror_rate": self.get_rerror_rate(),  
            "srv_rerror_rate": self.get_srv_rerror_rate(),  
            "same_srv_rate": self.get_same_srv_rate(),  
            "diff_srv_rate": self.get_diff_srv_rate(),  
            "srv_diff_host_rate": self.get_srv_diff_host_rate(), 
            "dst_host_count": self.get_dst_host_count(packet),  
            "dst_host_srv_count": self.get_dst_host_srv_count(packet), 
            "dst_host_same_srv_rate": self.get_dst_host_same_srv_rate(packet), 
            "dst_host_diff_srv_rate": self.get_dst_host_diff_srv_rate(packet), 
            "dst_host_same_src_port_rate": self.get_dst_host_same_src_port_rate(packet), 
            "dst_host_srv_diff_host_rate":0, 
            "dst_host_serror_rate": self.get_dst_host_serror_rate(packet),  
            "dst_host_srv_serror_rate": self.get_dst_host_srv_serror_rate(packet), 
            "dst_host_rerror_rate": self.get_dst_host_rerror_rate(packet), 
            "dst_host_srv_rerror_rate": self.get_dst_host_srv_rerror_rate(packet)  
        }

        
        if IP in packet:
            ip_layer = packet[IP]
            features["protocol_type"] = ip_layer.proto
            features["dst_bytes"] = len(packet) 
            
            features["land"] = str(int(ip_layer.src == ip_layer.dst))
            tflag="SF"
            if TCP in packet:
                features["service"] = "tcp"
                self.serv_count += 1
                self.service_count["tcp"] += 1
                
                if packet[TCP].flags == 0x12:  # SYN-ACK
                    tflag = "S3"  
                elif packet[TCP].flags == 0x02:  # SYN
                    tflag = "S1" 
                elif packet[TCP].flags == 0x04:  # RST
                    self.rerror_count+=1
                    if packet[TCP].dport == 80:  # Assuming rejection on web server
                        tflag = "REJ"  # Rejected
                    else:
                        tflag = "RSTO"  # RST from origin
                elif packet[TCP].flags == 0x10:  # ACK
                    tflag = "SH"  # Half connection, example
                else:
                    tflag = "OTH"  # Other state
            
                
            elif UDP in packet:
                features["service"] = "udp"
                self.serv_count += 1
                self.service_count["udp"] += 1
            elif ICMP in packet:
                features["service"] = "icmp"
                self.serv_count += 1
                self.service_count["icmp"] += 1
            features['flag']=tflag
        return features

    def get_srv_count(self, packet):
        return len(set(self.service_count))

    def get_serror_rate(self):
        # Returns the server error rate
        p_total = self.serv_count + self.srv_count + self.serror_count + self.rerror_count
        return self.serror_count / p_total if p_total > 0 else 0

    def get_srv_serror_rate(self):
        # Similar calculation for same service errors
        total_service = self.service_count.get('tcp', 0) + self.service_count.get('udp', 0)
        return self.serror_count / total_service if total_service > 0 else 0

    def get_rerror_rate(self):
        # Overall client error rate
        return self.rerror_count / self.packet_count if self.packet_count > 0 else 0

    def get_srv_rerror_rate(self):
        # Same service rerror rate
        if self.service_count.get('tcp', 1)>0:
            return self.rerror_count / self.service_count.get('tcp', 1)
        else:
            return 0

    def get_same_srv_rate(self):
        current_time = time.time()
        if self.packet_count == 0:
            return 1.0
        # Rate of same service usage
        same_srv = sum(1 for count in self.service_count.values() if count > 1)
        return same_srv / self.packet_count

    def get_diff_srv_rate(self):
        return len(self.service_count)

    def get_srv_diff_host_rate(self):
        # Maintain track of different host services here
        return 0.0  # Place logic here as needed

    def get_dst_host_count(self, packet):
        if IP in packet:
            destination = packet[IP].dst
            self.dst_host_count[destination] += 1
            return self.dst_host_count[destination]
        return 0

    def get_dst_host_srv_count(self, packet):
        if IP in packet and TCP in packet:
            return self.service_count["tcp"]
        return 0

    def get_dst_host_same_srv_rate(self, packet):
        return len([service for service in self.service_count])

    def get_dst_host_diff_srv_rate(self, packet):
        return len(self.dst_host_count)

    def get_dst_host_same_src_port_rate(self, packet):
        if IP in packet:
            return self.src_port_count[packet[IP].sport]  
        else:
            return 0

    def get_dst_host_serror_rate(self, packet):
        return self.serror_count / self.packet_count if self.packet_count > 0 else 0

    def get_dst_host_srv_serror_rate(self, packet):
        return self.get_dst_host_serror_rate(packet)

    def get_dst_host_rerror_rate(self, packet):
        return self.get_rerror_rate()

    def get_dst_host_srv_rerror_rate(self, packet):
        return self.get_srv_rerror_rate()

    def send_to_ml_server(self, features):
        try:
            response = requests.post(ML_SERVER_URL, json=features)
            if response.status_code == 200:
                print(f"Response from ML Server: {response.json()}")
            else:
                print(f"Failed to get response from ML Server, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error sending data to ML server: {e}")

    def packet_handler(self, packet):
        # Extract features from the packet
        features = self.extract_features(packet)
        print(f"Extracted Features: {features}")

        # Send the extracted features to the ML server
        self.send_to_ml_server(features)

        self.packet_count += 1
        print(f"Total Packets Processed: {self.packet_count}")

    def start_sniffing(self):
        print("Starting packet sniffing...")
        
        sniff(prn=self.packet_handler, filter="tcp", store=0)
        
if __name__ == "__main__":
    capture_engine = PacketCaptureEngine()
    capture_engine.start_sniffing()

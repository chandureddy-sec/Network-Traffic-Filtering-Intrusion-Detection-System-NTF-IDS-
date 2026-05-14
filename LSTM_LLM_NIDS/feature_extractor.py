import time
import uuid

try:
    from scapy.all import IP, TCP, UDP, ICMP
except ImportError:
    IP, TCP, UDP, ICMP = None, None, None, None

last_time = time.time()

def extract_features(packet):
    """
    Parses a raw Scapy packet into a human-readable dictionary and a 
    normalized numerical vector tailored for LSTM time-series ingestion.
    """
    global last_time
    
    current_time = time.time()
    time_delta = current_time - last_time
    last_time = current_time
    
    # Base schema default values
    packet_info = {
        "packet_id": str(uuid.uuid4())[:8],
        "length": len(packet),
        "protocol": "Other",
        "protocol_num": 0,  # 0=Other, 1=TCP, 2=UDP, 3=ICMP
        "src_ip": "Unknown",
        "dst_ip": "Unknown",
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0,
        "time_delta": round(time_delta, 4)
    }
    
    if IP in packet:
        packet_info["length"] = len(packet[IP])
        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst
        
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["protocol_num"] = 1
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["tcp_flags"] = int(packet[TCP].flags)
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["protocol_num"] = 2
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            packet_info["protocol_num"] = 3
            
    # Vector Normalization for LSTM (Timestep shape: [1, 6])
    vector = [
        min(packet_info["length"] / 1500.0, 1.0),     # Scale length
        packet_info["protocol_num"] / 3.0,            # Scale Protocol
        packet_info["src_port"] / 65535.0,            # Scale Source Port
        packet_info["dst_port"] / 65535.0,            # Scale Dest Port
        packet_info["tcp_flags"] / 63.0,              # Scale Flags
        min(packet_info["time_delta"], 1.0)           # Cap time frequency variance
    ]
    
    return packet_info, vector

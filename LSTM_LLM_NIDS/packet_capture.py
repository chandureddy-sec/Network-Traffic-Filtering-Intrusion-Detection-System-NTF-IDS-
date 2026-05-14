import threading
import time
from collections import deque

try:
    from scapy.all import sniff, rdpcap
except ImportError:
    sniff, rdpcap = None, None

from feature_extractor import extract_features

# Global queue safely shuttling traffic from Background Threads -> Streamlit Dashboard
packet_queue = deque()  

is_capturing = False
capture_thread = None

def _process_packet(pkt):
    """Callback for every packet parsed by Scapy."""
    if not is_capturing:
        return
    info, vector = extract_features(pkt)
    packet_queue.append((info, vector))

def _sniff_loop(interface):
    """
    Continuous background loop snapping 10 packets per cycle.
    Using chunking correctly ensures the thread isn't blocked infinitely
    and `is_capturing` flag halts cleanly.
    """
    global is_capturing
    while is_capturing:
        try:
            if interface and interface != "Default" and interface != "Loopback":
                sniff(iface=interface, count=10, prn=_process_packet, timeout=2.0, store=False)
            else:
                sniff(count=10, prn=_process_packet, timeout=2.0, store=False)
        except Exception as e:
            print(f"[!] Sniff iteration error (Requires Npcap/Admin): {e}")
            time.sleep(1)

def start_live_capture(interface="Default"):
    """Bootstraps the non-blocking thread."""
    global is_capturing, capture_thread
    if is_capturing: 
        return
    is_capturing = True
    packet_queue.clear()
    capture_thread = threading.Thread(target=_sniff_loop, args=(interface,), daemon=True)
    capture_thread.start()

def stop_capture():
    """Signals sniff loop to break."""
    global is_capturing
    is_capturing = False

def load_pcap(filepath):
    """Alternative pipeline to load synthetic/historic DOS files directly into queue."""
    global is_capturing
    stop_capture()
    packet_queue.clear()
    try:
        packets = rdpcap(filepath)
        for pkt in packets:
            info, vector = extract_features(pkt)
            packet_queue.append((info, vector))
        return True, len(packets)
    except Exception as e:
        return False, str(e)

def pop_queue():
    """Safely retrieves packet for dashboard ingest."""
    if len(packet_queue) > 0:
        return packet_queue.popleft()
    return None

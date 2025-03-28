import pyshark
import pandas as pd
from src.parse_data import *
from src.detect_scan_port import scans
from src.detect_anomalies import detect_anomalies
import threading
from queue import Queue

def analyze_packet(packet):
    try:
        if 'IP' in packet:
            return {
                'src': packet.ip.src,
                'dst': packet.ip.dst,
                'proto': protocol_map.get(int(packet.ip.proto), str(packet.ip.proto)),
                'length': int(packet.length),
                'timestamp': packet.sniff_time,
                'src_port': int(packet[packet.transport_layer].srcport) if hasattr(packet, 'transport_layer') else None,
                'dst_port': int(packet[packet.transport_layer].dstport) if hasattr(packet, 'transport_layer') else None,
                'conn_state': interpret_tcp_flags(int(packet.tcp.flags, 16)) if 'TCP' in packet else None,
                'duration': packet.tcp.time if 'TCP' in packet and hasattr(packet.tcp, 'time') else None,
                'DNS': packet.dns.qry_name if 'DNS' in packet and hasattr(packet.dns, 'qry_name') else None
            }
    except AttributeError:
        pass
    return None

def live_detect_scan(interface='eth0'):
    print(f"Real-time capture on interface {interface}...")
    capture = pyshark.LiveCapture(interface=interface)
    packet_queue = Queue()
    batch_size = 1000  # Number of packets to accumulate before analysis

    def analyze():
        while True:
            batch = []
            while len(batch) < batch_size:
                packet_info = packet_queue.get()  # Blocks until a packet is available
                batch.append(packet_info)
            # Process the batch of packets
            df = pd.DataFrame(batch)
            scans(df) # port scan detection
            detect_anomalies(df, 'length', filter="proto == " + str(protocol_map['tcp'])) # anomaly detection

    # Start a thread for analysis
    analysis_thread = threading.Thread(target=analyze, daemon=True)
    analysis_thread.start()

    try:
        for packet in capture.sniff_continuously(packet_count=None):
            packet_info = analyze_packet(packet)
            if packet_info:
                packet_queue.put(packet_info)  # Add the packet to the queue
    except KeyboardInterrupt:
        print("\nInterrupt detected. Stopping capture...")
    finally:
        capture.close()

if __name__ == "__main__":
    interface = input("Enter the network interface to monitor (default: eth0): ") or "eth0"
    live_detect_scan(interface)
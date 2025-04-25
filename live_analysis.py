import pyshark
import pandas as pd
from src.parse_data import *
from src.basic_stat import ip_nbPort, ip_connexionTime, destPort_nbConnexion, maxLength_ip
from src.detect_anomalies import detect_anomalies  # Import de la fonction pour détecter les anomalies
import threading
from queue import Queue

def analyze_packet(packet):
    """
    Analyzes a network packet and extracts relevant information.
    """
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
    """
    Captures and analyzes network traffic in real-time on a given interface.
    """
    print(f"Real-time capture on interface {interface}...")
    capture = pyshark.LiveCapture(interface=interface, display_filter='ip')
    packet_queue = Queue(maxsize=10000)
    batch_size = 1000 
    output_file = "data/live_analyzed_data.csv"

    # Initialize the output file
    with open(output_file, 'w') as f:
        f.write("src,dst,proto,length,timestamp,src_port,dst_port,conn_state,duration,DNS\n")

    def analyze():
        """
        Processes batches of packets from the queue and detects anomalies.
        """
        while True:
            batch = []
            while len(batch) < batch_size:
                packet_info = packet_queue.get(timeout=1)  # Blocks until a packet is available
                batch.append(packet_info)
            # Process the batch of packets
            df = pd.DataFrame(batch)

            # Save the data to the output file
            df.to_csv(output_file, mode='a', header=False, index=False)

            try:
                # Détection de scans de ports
                port_scan_anomalies = detect_anomalies(df, column='dst_port', threshold=100)
                if not port_scan_anomalies.empty:
                    print("\n=== Scans de ports détectés ===")
                    print(port_scan_anomalies)

                # Détection de transferts volumineux
                data_anomalies = detect_anomalies(df, column='length')
                if not data_anomalies.empty:
                    print("\n=== Transferts de données suspects ===")
                    print(data_anomalies)
                    
                # Analyse des connexions par IP
                IP_anomalies = detect_anomalies(df, column='src')
                if not IP_anomalies.empty:
                    print("\n=== Anomalies de connexion par IP ===")
                    print(IP_anomalies)
                    
            except Exception as e:
                print(f"Error processing data for anomaly detection: {e}")

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
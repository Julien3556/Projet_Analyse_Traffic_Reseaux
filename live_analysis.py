import pyshark
import pandas as pd
from src.parse_data import *
from src.detect_scan_port import scans
from src.detect_anomalies import detect_anomalies
from src.basic_stat import ip_nbPort, ip_connexionTime, destPort_nbConnexion, maxLength_ip
import threading
from queue import Queue
import matplotlib.pyplot as plt

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
    packet_queue = Queue()
    batch_size = 1000  # Number of packets to accumulate before analysis
    output_file = "analyzed_data.csv"

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
                packet_info = packet_queue.get()  # Blocks until a packet is available
                batch.append(packet_info)
            # Process the batch of packets
            df = pd.DataFrame(batch)

            # Save the data to the output file
            df.to_csv(output_file, mode='a', header=False, index=False)

            # Generate real-time visualizations
            plt.ion()  # Enable interactive mode
            plt.figure(figsize=(10, 6))

            # Call functions from basic_stat to generate diagrams
            try:
                ip_nbPort(df)
                ip_connexionTime(df)
                destPort_nbConnexion(df)
                maxLength_ip(df)
            except Exception as e:
                print(f"Error generating diagrams: {e}")

            plt.pause(0.1)  # Pause to update the plots
            plt.clf()  # Clear the figure for the next batch

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
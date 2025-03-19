import pyshark
import pandas as pd
from src.parse_data import protocol_map, interpret_tcp_flags
from src.detect_scan_port import scans  # Importez votre fonction de détection de scans

def analyze_packet(packet):
    """
    Analyse un paquet capturé et extrait des informations utiles.

    Args:
        packet: Un paquet capturé par pyshark.

    Returns:
        dict: Les informations extraites du paquet (ou None si le paquet ne contient pas d'informations IP).
    """
    try:
        if 'IP' in packet:
            src = packet.ip.src
            dst = packet.ip.dst
            proto_num = int(packet.ip.proto)
            proto = protocol_map.get(proto_num, str(proto_num))
            length = int(packet.length)
            timestamp = packet.sniff_time
            src_port = int(packet[packet.transport_layer].srcport) if hasattr(packet, 'transport_layer') and packet.transport_layer and hasattr(packet[packet.transport_layer], 'srcport') else None
            dst_port = int(packet[packet.transport_layer].dstport) if hasattr(packet, 'transport_layer') and packet.transport_layer and hasattr(packet[packet.transport_layer], 'dstport') else None
            conn_state = interpret_tcp_flags(int(packet.tcp.flags, 16)) if 'TCP' in packet and hasattr(packet, 'tcp') else None
            duration = packet.tcp.time if 'TCP' in packet and hasattr(packet.tcp, 'time') else None
            dns = packet.dns.qry_name if 'DNS' in packet and hasattr(packet.dns, 'qry_name') else None

            return {
                'src': src,
                'dst': dst,
                'proto': proto,
                'length': length,
                'timestamp': timestamp,
                'src_port': src_port,
                'dst_port': dst_port,
                'conn_state': conn_state,
                'duration': duration,
                'DNS': dns
            }
    except AttributeError as e:
        print(f"Erreur lors de l'analyse du paquet : {e}")
    return None

def live_detect_scan(interface='eth0'):
    """
    Capture et analyse les paquets réseau en temps réel pour détecter les scans de ports.

    Args:
        interface (str): L'interface réseau à surveiller (par défaut : 'eth0').

    Returns:
        None
    """
    print(f"Capture en temps réel sur l'interface {interface}...")
    capture = pyshark.LiveCapture(interface=interface)
    data = []

    try:
        for packet in capture.sniff_continuously():
            # Analyse du paquet capturé
            packet_info = analyze_packet(packet)
            if packet_info:
                data.append(packet_info)

            # Analyse des données accumulées toutes les 100 paquets
            if len(data) >= 1000:
                df = pd.DataFrame(data)
                print("Analyse des paquets capturés...")
                scans(df)  # Appel à votre fonction de détection de scans
                data.clear()  # Réinitialiser les données après l'analyse
    except KeyboardInterrupt:
        print("\nInterruption détectée. Arrêt de la capture...")
    finally:
        capture.close()  # Fermer proprement la capture

# Exemple d'utilisation
if __name__ == "__main__":
    interface = input("Entrez l'interface réseau à surveiller (par défaut : eth0) : ") or "eth0"
    live_detect_scan(interface)
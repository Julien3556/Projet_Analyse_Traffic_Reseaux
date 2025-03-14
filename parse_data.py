import pandas as pd
import pyshark as ps

# Dictionnaire de mappage des numéros de protocole aux noms de protocole
protocol_map = {
    1: 'ICMP',       # Internet Control Message Protocol
    2: 'IGMP',       # Internet Group Management Protocol
    6: 'TCP',        # Transmission Control Protocol
    17: 'UDP',       # User Datagram Protocol
    41: 'IPv6',      # IPv6 encapsulation
    47: 'GRE',       # Generic Routing Encapsulation
    50: 'ESP',       # Encapsulating Security Payload
    51: 'AH',        # Authentication Header
    58: 'ICMPv6',    # ICMP for IPv6
    89: 'OSPF',      # Open Shortest Path First
    132: 'SCTP',     # Stream Control Transmission Protocol
    137: 'MPLS-in-IP' # MPLS in IP
}

def interpret_tcp_flags(flags):
    flag_descriptions = {
        0x0002: 'SYN',
        0x0010: 'ACK',
        0x0001: 'FIN',
        0x0004: 'RST',
        0x0008: 'PSH',
        0x0012: 'SYN-ACK',
        0x0018: 'PSH-ACK',
        0x0011: 'FIN-ACK',
        0x0014: 'RST-ACK'
    }
    return flag_descriptions.get(flags, 'UNKNOWN')

def parse_pcap(file):
    data = []
    cap = ps.FileCapture(file)
    for package in cap:
        if 'IP' in package:
            src = package.ip.src
            dst = package.ip.dst
            proto_num = int(package.ip.proto)
            proto = protocol_map.get(proto_num, str(proto_num))
            length = int(package.length)
            timestamp = package.sniff_time
            src_port = int(package[package.transport_layer].srcport) if hasattr(package, 'transport_layer') and package.transport_layer and hasattr(package[package.transport_layer], 'srcport') else None
            dst_port = int(package[package.transport_layer].dstport) if hasattr(package, 'transport_layer') and package.transport_layer and hasattr(package[package.transport_layer], 'dstport') else None
            conn_state = interpret_tcp_flags(int(package.tcp.flags, 16)) if 'TCP' in package and hasattr(package, 'tcp') else None
            duration = package.tcp.time if 'TCP' in package and hasattr(package.tcp, 'time') else None
            dns = package.dns.qry_name if 'DNS' in package and hasattr(package.dns, 'qry_name') else None
            data.append([src, dst, proto, length, timestamp, src_port, dst_port, conn_state, duration, dns])
    return pd.DataFrame(data, columns=['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state', 'duration', 'DNS'])

def parse_log(file):
    columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents', 'threat', 'sample']
    dataFrame = pd.read_csv(file, sep="\t", names=columns, na_values='-')
    dataFrame['ts'] = pd.to_datetime(dataFrame['ts'], errors='coerce')
    dataFrame['id.orig_p'] = pd.to_numeric(dataFrame['id.orig_p'], errors='coerce').fillna(0).astype(int)
    dataFrame['id.resp_p'] = pd.to_numeric(dataFrame['id.resp_p'], errors='coerce').fillna(0).astype(int)
    dataFrame['orig_bytes'] = pd.to_numeric(dataFrame['orig_bytes'], errors='coerce').fillna(0).astype(int)
    dataFrame['proto'] = dataFrame['proto'].astype(str)
    dataFrame['orig_bytes'] = pd.to_numeric(dataFrame['orig_bytes'], errors='coerce').fillna(0).astype(int)
    dataFrame['duration'] = pd.to_numeric(dataFrame['duration'], errors='coerce').fillna(0).astype(float)
    dataFrame['DNS'] = dataFrame['service'] if 'DNS' in dataFrame['service'] else None
    dataFrame = dataFrame.rename(columns={'id.orig_h': 'src', 'id.resp_h': 'dst', 'orig_bytes': 'length', 'ts': 'timestamp', 'id.orig_p': 'src_port', 'id.resp_p': 'dst_port'})
    return dataFrame[['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state', 'duration', 'service']]

def convert_data(file):
    if file.endswith('.pcap'):
        print("Le fichier courant est bien un .pcap")
        return parse_pcap(file)
    elif file.endswith('.log'):
        print("Le fichier courant est bien un .log")
        return parse_log(file)
    else:
        raise ValueError('Unsupported file type')

if __name__ == '__main__':
    data = convert_data('data/sample.pcap')
    data = convert_data('data/sample.pcap')
    print(data.sample(20))
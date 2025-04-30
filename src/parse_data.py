from os import replace
import pandas as pd
import pyshark as ps

# Dictionary mapping protocol numbers to protocol names
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
    """
    Interprets TCP flags and returns their description.

    Arguments:
        - flags: int, the TCP flags as a hexadecimal value.

    Returns:
        - str: Description of the TCP flags or 'UNKNOWN' if not recognized.
    """
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
    """
    Parses a PCAP file and extracts network packet data into a DataFrame.

    Arguments:
        - file: str, path to the PCAP file to analyze.

    Functionality:
        - Extracts source/destination IPs, protocol, length, timestamp, ports, and other details.
        - Maps protocol numbers to protocol names.
        - Interprets TCP flags and DNS queries if available.
        - Calculates connection durations for TCP connections.
        - Saves the extracted data to a CSV file.

    Returns:
        - pd.DataFrame: A DataFrame containing the extracted network packet information.
    """
    data = []
    connections = {}  # Dictionnaire pour suivre les connexions TCP
    cap = ps.FileCapture(file)
    if file.endswith('.pcap'):
        output_file = f"{file[:-5]}.csv"
    elif file.endswith('.pcapng'):
        output_file = f"{file[:-7]}.csv"

    for package in cap:
        if 'IP' in package:
            src = package.ip.src
            dst = package.ip.dst
            proto_num = int(package.ip.proto)
            proto = protocol_map.get(proto_num, str(proto_num))
            length = int(package.length)
            timestamp = float(package.sniff_timestamp) if hasattr(package, 'sniff_timestamp') else None
            src_port = int(package[package.transport_layer].srcport) if hasattr(package, 'transport_layer') and package.transport_layer and hasattr(package[package.transport_layer], 'srcport') else None
            dst_port = int(package[package.transport_layer].dstport) if hasattr(package, 'transport_layer') and package.transport_layer and hasattr(package[package.transport_layer], 'dstport') else None
            conn_state = interpret_tcp_flags(int(package.tcp.flags, 16)) if 'TCP' in package and hasattr(package, 'tcp') else None
            dns = package.dns.qry_name if 'DNS' in package and hasattr(package.dns, 'qry_name') else None

            # Suivi des connexions TCP
            if proto == 'TCP' and src_port and dst_port:
                conn_id = (src, dst, src_port, dst_port)
                if conn_id not in connections:
                    # Premier paquet de la connexion
                    connections[conn_id] = {'start': timestamp, 'end': timestamp}
                else:
                    # Mettre à jour le timestamp de fin
                    connections[conn_id]['end'] = timestamp
                

            # Ajouter les données du paquet
            data.append([src, dst, proto, length, timestamp, src_port, dst_port, conn_state, dns])

    # Calculer les durées des connexions
    connection_durations = {}
    for conn_id, times in connections.items():
        connection_durations[conn_id] = times['end'] - times['start']

    # Ajouter les durées au DataFrame
    df = pd.DataFrame(data, columns=['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state', 'DNS'])
    df['connection_duration'] = df.apply(
        lambda row: connection_durations.get((row['src'], row['dst'], row['src_port'], row['dst_port']), None)
        if row['proto'] == 'TCP' else None,
        axis=1)
    
    # Sauvegarder les données dans un fichier CSV
    if output_file:
        df.to_csv(output_file, index=False)
        print(f"Data saved to {output_file}")
    
    return df

def parse_log(file):
    """
    Parses a network log file and converts it into a DataFrame.

    Arguments:
        - file: str, path to the network log file.

    Functionality:
        - Reads the log file with predefined column names.
        - Converts timestamps and numeric fields to appropriate types.
        - Renames columns for consistency with other data sources.
        - Saves the transformed data to a CSV file.

    Returns:
        - pd.DataFrame: A DataFrame containing the transformed log data.
    """
    output_file = f"{file[:-4]}.csv"
    columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents', 'threat', 'sample']
    dataFrame = pd.read_csv(file, sep="\t", names=columns)
    dataFrame['ts'] = pd.to_datetime(dataFrame['ts'], errors='coerce')
    dataFrame['id.orig_p'] = pd.to_numeric(dataFrame['id.orig_p'], errors='coerce').fillna(0).astype(int)
    dataFrame['id.resp_p'] = pd.to_numeric(dataFrame['id.resp_p'], errors='coerce').fillna(0).astype(int)
    dataFrame['orig_bytes'] = pd.to_numeric(dataFrame['orig_bytes'], errors='coerce').fillna(0).astype(int)
    dataFrame['proto'] = dataFrame['proto'].astype(str)
    dataFrame['duration'] = pd.to_numeric(dataFrame['duration'], errors='coerce').fillna(0).astype(float)
    dataFrame['DNS'] = dataFrame['service'] if 'DNS' in dataFrame['service'] else None
    dataFrame = dataFrame.rename(columns={'id.orig_h': 'src', 'id.resp_h': 'dst', 'orig_bytes': 'length', 'ts': 'timestamp', 'id.orig_p': 'src_port', 'id.resp_p': 'dst_port'})
    # Save to a file if an output filename is provided
    if output_file:
        dataFrame.to_csv(output_file, index=False)
        print(f"Data saved to {output_file}")   
    return dataFrame

def convert_data(file):
    """
    Converts data from a file based on its type.

    Arguments:
        - file: str, path to the file to process.

    Functionality:
        - Determines the file type based on its extension (.pcap or .log).
        - Calls the appropriate parsing function (`parse_pcap` or `parse_log`).

    Returns:
        - object: The result of processing the file.

    Exceptions:
        - ValueError: If the file has an unsupported extension.
    """
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        print("The current file is indeed a .pcap file.")
        return parse_pcap(file)
    elif file.endswith('.log'):
        print("The current file is indeed a .log file.")
        return parse_log(file)
    else:
        raise ValueError('Unsupported file type')

if __name__ == '__main__':
    data = convert_data('data/tcp-traceroute.pcapng')
    print(data.sample(20))
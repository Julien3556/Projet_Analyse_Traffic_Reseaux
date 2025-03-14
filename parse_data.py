import pandas as pd
import pyshark as ps

def parse_pcap(file):
    data = []
    cap = ps.FileCapture(file)
    for package in cap:
        if 'IP' in package:
            src = package.ip.src
            dst = package.ip.dst
            proto = int(package.ip.proto)
            length = int(package.length)
            timestamp = package.sniff_time
            src_port = int(package[package.transport_layer].srcport) if hasattr(package, package.transport_layer) else None
            dst_port = int(package[package.transport_layer].dstport) if hasattr(package, package.transport_layer) else None
            conn_state = package.tcp.flags if 'TCP' in package else None
            data.append([src, dst, proto, length, timestamp, src_port, dst_port, conn_state])
    return pd.DataFrame(data, columns=['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state'])

def parse_log(file):
    columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents', 'threat', 'sample']
    dataFrame = pd.read_csv(file, sep="\t", names=columns, na_values='-')
    dataFrame['ts'] = pd.to_datetime(dataFrame['ts'], errors='coerce')
    dataFrame['id.orig_p'] = pd.to_numeric(dataFrame['id.orig_p'], errors='coerce').fillna(0).astype(int)
    dataFrame['id.resp_p'] = pd.to_numeric(dataFrame['id.resp_p'], errors='coerce').fillna(0).astype(int)
    dataFrame['orig_bytes'] = pd.to_numeric(dataFrame['orig_bytes'], errors='coerce').fillna(0).astype(int)
    dataFrame['proto'] = dataFrame['proto'].astype(str)
    dataFrame['orig_bytes'] = pd.to_numeric(dataFrame['orig_bytes'], errors='coerce').fillna(0).astype(int)
    dataFrame = dataFrame.rename(columns={'id.orig_h': 'src', 'id.resp_h': 'dst', 'orig_bytes': 'length', 'ts': 'timestamp', 'id.orig_p': 'src_port', 'id.resp_p': 'dst_port'})
    return dataFrame[['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state']]

def convert_data(file):
    if file.endswith('.pcap'):
        return parse_pcap(file)
    elif file.endswith('.log'):
        return parse_log(file)
    else:
        raise ValueError('Unsupported file type')

if __name__ == '__main__':
    data = convert_data('data/conn_sample.log')
    print(data.sample(20))
    
    df = pd.DataFrame(data)
    
    # Convertir le DataFrame en log
    def create_log_from_df(dataframe, log_filename):
        with open(log_filename, 'w') as f:
            for _, row in dataframe.iterrows():
                log_line = (
                    f"[{row['timestamp']}] - "
                    f"SRC: {row['src']} - DST: {row['dst']} - "
                    f"PROTO: {row['proto']} - LENGTH: {row['length']} - "
                    f"SRCPORT: {row['src_port']} - DSTPORT: {row['dst_port']} - "
                    f"CONN_STATE: {row['conn_state']}\n"
                )
                f.write(log_line)

    # Appeler la fonction pour créer le fichier .log
    create_log_from_df(df, 'network_log.log')

    print("Fichier network_log.log créé avec succès.")
import pandas as pd

columns = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','threat','sample']
dataFrame = pd.read_csv("conn_sample.log", sep="\s+", names=columns)

port_scan_attempts = dataFrame.groupby("id.orig_h")["id.resp_p"].nunique()
suspected_scanners = port_scan_attempts[port_scan_attempts > 50]

rejected_connections = dataFrame[dataFrame["conn_state"] == "REJ"]
connections_rejected = rejected_connections.groupby("id.orig_h").size()


fusion = port_scan_attempts.index.intersection(connections_rejected.index)
print(list(fusion))

print("IPs suspectées de scan de ports: ")
"""
print(suspected_scanners)
print(len(suspected_scanners))
"""
import pandas as pd

def scans(dataFrame, threshold):
    """
    Detects port scan attempts in a network DataFrame.
    
    Arguments:
        - dataFrame: pandas.DataFrame with columns "src", "dst_port", "conn_state".
        - threshold: int, threshold of distinct ports to suspect a scan.
    
    Functionality:
        - Counts the distinct destination ports contacted by each source IP.
        - Identifies suspicious IPs exceeding the threshold.
        - Filters rejected connections ("REJ") by source IP.
        - Finds common IPs between suspects and rejected connections.
        - Displays suspicious IPs or a message if none are detected.
    """
    
    # Count the number of distinct destination ports contacted by each source IP
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique()
    suspected_scanners = port_scan_attempts[port_scan_attempts > threshold]

    # Filter connections that were rejected
    rejected_connections = dataFrame[dataFrame["conn_state"] == "REJ"]
    connections_rejected = rejected_connections.groupby("src").size()

    # Find common source IPs between suspected scanners and rejected connections
    fusion = suspected_scanners.index.intersection(connections_rejected.index)

    if len(fusion) == 0:
        print("No IPs suspected of port scanning")
    else:
        print("IPs suspected of port scanning: ")
        print(list(fusion))
        print("\n🚨 PORT SCAN DETECTED 🚨\n", "Count: ", len(fusion), "\n")
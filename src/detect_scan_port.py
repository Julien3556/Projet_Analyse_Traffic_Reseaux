# Importation des bibliothèques nécessaires
import pandas as pd

def scans(dataFrame, threshold):
    # Count the number of distinct destination ports contacted by each source IP
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique()
    suspected_scanners = port_scan_attempts[port_scan_attempts > threshold]

    # Filter connections that were rejected
    rejected_connections = dataFrame[dataFrame["conn_state"] == "REJ"]
    connections_rejected = rejected_connections.groupby("src").size()

    # Find common source IPs between suspected scanners and rejected connections
    fusion = suspected_scanners.index.intersection(connections_rejected.index)

    if len(fusion) == 0:
        print("Aucune IP suspectée de scan de ports")
    else:
        print("IPs suspectées de scan de ports: ")
        print(list(fusion))
        print("\n🚨 SCAN DE PORTS DÉTECTÉ 🚨\n", "Nb : ", len(fusion), "\n")


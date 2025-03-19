# Importation des bibliothèques nécessaires
import pandas as pd
from src.parse_data import parse_log

def scans(dataFrame):
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique() # Tableau qui comprend un grand nb de connexions
    threshold = int(input("Select the threshold : "))
    suspected_scanners = port_scan_attempts[port_scan_attempts > threshold]

    rejected_connections = dataFrame[dataFrame["conn_state"] == "REJ"] # Tableau qui comprend les connexions rejetées
    connections_rejected = rejected_connections.groupby("src").size()

    fusion = port_scan_attempts.index.intersection(connections_rejected.index) # Tableau qui fusionne les 2 tableaux précédents
    

    print("IPs suspectées de scan de ports: ")
    print(list(fusion))
    print("\n🚨 SCAN DE PORTS DÉTECTÉ 🚨\n", "Nb : ", fusion.size, "\n")

if __name__ == '__main__':
    # Utiliser parse_log pour charger les données
    dataFrame = parse_log("data/conn_sample.log")
    scans(dataFrame)
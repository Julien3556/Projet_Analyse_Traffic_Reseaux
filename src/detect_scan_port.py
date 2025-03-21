# Importation des bibliothèques nécessaires
def scans(dataFrame):
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique() # Tableau qui comprend un grand nb de connexions
    threshold = int(input("Select the threshold : "))
    suspected_scanners = port_scan_attempts[port_scan_attempts > threshold]

    rejected_connections = dataFrame[dataFrame["conn_state"] == "REJ"] # Tableau qui comprend les connexions rejetées
    connections_rejected = rejected_connections.groupby("src")

    fusion = port_scan_attempts.index.intersection(connections_rejected.index) # Tableau qui fusionne les 2 tableaux précédents
    

    if fusion.size == 0:
        return
    else:
        print("IPs suspectées de scan de ports: ")
        print(list(fusion))
        print("\n🚨 SCAN DE PORTS DÉTECTÉ 🚨\n", "Nb : ", fusion.size, "\n")


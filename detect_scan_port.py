# Importation des bibliothèques nécessaires
import pandas as pd
def scans(dataFrame):
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique() # Tableau qui comprend un grand nb de connexions
    suspected_scanners = port_scan_attempts[port_scan_attempts > 50]

    rejected_connections = dataFrame[dataFrame["conn_state"] == "REJ"] # Tableau qui comprend les connexions rejetés
    connections_rejected = rejected_connections.groupby("src").size()


    fusion = port_scan_attempts.index.intersection(connections_rejected.index) # Tableau qui fusionne les 2 tableaux précédents
    print(list(fusion))

    print("IPs suspectées de scan de ports: ")
    
    print(fusion)
    print("\n🚨 SCAN DE PORTS DÉTECTÉ 🚨\n", "Nb : ", fusion.size, "\n")
    """
    print(len(suspected_scanners))
    """
            
if __name__ == '__main__':
    columns = ['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state']
    dataFrame = pd.read_csv("conn_sample.log", sep="\s+", names=columns)


        
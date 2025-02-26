import pandas as pd

# columns = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','threat','sample']
# dataFrame = pd.read_csv("conn_sample.log", sep="\s+", names=columns)


class Scans :
    def __init__(self, dataFrame):
        self.dataFrame = dataFrame
        
    def test(self):
        print("test")
        
    def scans(self):
        port_scan_attempts = self.dataFrame.groupby("id.orig_h")["id.resp_p"].nunique() #Tableau grand nb de connexions
        suspected_scanners = port_scan_attempts[port_scan_attempts > 50]

        rejected_connections = self.dataFrame[self.dataFrame["conn_state"] == "REJ"] #Tableau de connexions rejetés
        connections_rejected = rejected_connections.groupby("id.orig_h").size()


        fusion = port_scan_attempts.index.intersection(connections_rejected.index)
        print(list(fusion))

        print("IPs suspectées de scan de ports: ")
        
        print(fusion)
        print("\n🚨 SCAN DE PORTS DÉTECTÉ 🚨\n", "Nb : ", fusion.size, "\n")
        """
        print(len(suspected_scanners))
        """
    def scans2(self):
        rej = input("\n Connexions rejetées uniquement (True ou False) : ")

        if rej == "True":
            scan_attempts = self.dataFrame[self.dataFrame["conn_state"] == "REJ"].groupby("id.orig_h").size()
            print("Prise en compte uniquement des requêtes rejetées")
        else :
            print("Prise en compte des requêtes rejetées et non rejetées")
            
        scan_attempts = self.dataFrame.groupby("id.orig_h").size()
        try :
            seuil = int(input("\n Nombre de tentatives rejetées (int) : ")) # Seuil
            scan_attempts = scan_attempts[scan_attempts > seuil]  
            print("\n🚨 SCAN DE PORTS DÉTECTÉ 🚨\n", "Nb : ", scan_attempts.size, "\n")
        except:
            print("Erreur vous devez utiliser un entier.")



        
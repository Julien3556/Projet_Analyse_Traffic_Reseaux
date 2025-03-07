# Importation
import pandas as pd
import detect_scan_port as sp
import parse_data as pa
import detect_http_suspect as d
import os

# Définition des noms de colonnes
columns = [
    'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration',
    'orig_bytes','resp_bytes','conn_state','local_orig','missed_bytes','history',
    'orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','threat','sample'
]

# Charger les logs dans un DataFrame
dataFrame = pd.read_csv("conn_sample.log", sep="\t", names=columns, engine="python")

# Correction du format timestamp
dataFrame['ts'] = pd.to_datetime(dataFrame['ts'].astype(float), unit='s')

file = 'conn_sample.log'

if __name__ == "__main__" :
    while True:
        print("\n===Commandes possibles=== \n\n1-Select file (select) \n2-Afficher les logs (print) \n3-Scans de ports (sp) \n \n5-Convertisseur de data (convert) \n6-Detection http suspecte (http)")
        commandes = input(">>> : ")
        
        match commandes.lower():
            case "quitter" | "q":
                print("Déconnexion réussie")
                break
            
            case "afficher":
                print(dataFrame.head())

            case "select":
                repertoire = "dossier"
                extension = ".pcap"

                print("Vous avez tous ces fichiers : ")
                
                for fichier in os.listdir(repertoire):
                    if fichier.endswith(extension):
                        print(fichier)
                        
                buffer_file = input("File name : ")
                
                if os.path.isfile(buffer_file):
                    file = buffer_file
                    print("Le fichier a bien été pris en compte")
                else:
                    print("Le fichier n'existe pas.")

            case "sp":
                sp.scans(dataFrame)

            case "convert":
                data = pa.convert_data(file)
                print(data.sample(20))

            case "http":
                d.detect(dataFrame)

            case _:
                print("Erreur de commande")

# Importation
import pandas as pd
import detect_scan_port as sp

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


if __name__ == "__main__" :
    while True:
        print("\n\Commandes possibles : afficher, scans de ports (sp), scans de ports2 (sp2)")
        commandes = input(">>> : ")
        
        if commandes == "quitter" or commandes == "q":
            print("Déconnexion réussie")
            break
        
        elif commandes == "afficher":
            print(dataFrame.head())
            
        elif commandes == "scans de ports" or commandes == "sp":
            scan = sp.Scans(dataFrame)
            scan.scans()

        elif commandes == "scans de ports2" or commandes == "sp2":
            scan2 = sp.Scans(dataFrame)
            scan2.scans2()
    
        else:
            print("Erreur de commande")
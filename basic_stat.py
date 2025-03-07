# Importation des bibliothèques nécessaires
import pandas as pd  
import matplotlib.pyplot as plt  

def ip_nbPort(dataFrame):
    # Comptage du nombre de ports distincts contactés par chaque adresse IP source (id.orig_h)
    port_scan_attempts = dataFrame.groupby("id.orig_h")["id.resp_p"].nunique()

    # Filtrage : on ne garde que les IP ayant contacté plus de 50 ports distincts
    # Création du graphique
    limit = int(input("Select the minimum number of ports : "))
    port_scan_attempts = port_scan_attempts[port_scan_attempts > limit]
    print(port_scan_attempts[0][0])
    port_scan_attempts.plot(kind="bar", color="skyblue", edgecolor="black")

    # Ajout des labels et du titre au graphique
    plt.xlabel("Adresse IP source")  
    plt.ylabel("Nombre de ports distincts contactés")  
    plt.title("Nombre de tentatives de connexion par adresse IP")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  

    # Affichage du graphique
    plt.show()



if __name__ == '__main__':
    # Définition des colonnes du fichier de logs
    columns = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service',
        'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'missed_bytes',
        'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents',
        'threat', 'sample'
    ]
    # Chargement du fichier de logs dans un DataFrame pandas
    dataFrame = pd.read_csv("./data/conn_sample.log", sep="\s+", names=columns)
    ip_nbPort(dataFrame)


# Importation des bibliothèques nécessaires
import pandas as pd  
import matplotlib.pyplot as plt  
from parse_data import parse_log

def ip_nbPort(dataFrame, local:bool):
    # Comptage du nombre de ports distincts contactés par chaque adresse IP source (id.orig_h)
    port_scan_attempts = dataFrame.groupby("id.orig_h")["id.resp_h"].nunique()
    print(port_scan_attempts)
    # Filtrage : on ne garde que les IP ayant contacté plus de 50 ports distincts
    # Création du graphique
    limit = int(input("Select the minimum number of ports : "))
    port_scan_attempts = port_scan_attempts[port_scan_attempts > limit]
    if(local):
        port_scan_attempts.index = port_scan_attempts.index.str[12:]
    port_scan_attempts.plot(kind="bar", color="skyblue", edgecolor="black")

    # Ajout des labels et du titre au graphique
    plt.xlabel("Adresse IP source")  
    plt.ylabel("Nombre de ports distincts contactés")  
    plt.title("Nombre de tentatives de connexion par adresse IP")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  

    # Affichage du graphique
    plt.show()


def time_connection(dataFrame):
    pass



if __name__ == '__main__':
    # Définition des colonnes du fichier de logs
    dataFrame = parse_log("./data/conn_sample.log")
    ip_nbPort(dataFrame, True)



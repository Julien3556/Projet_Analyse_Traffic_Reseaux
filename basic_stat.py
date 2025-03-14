# Importation des bibliothèques nécessaires
import pandas as pd  
import matplotlib.pyplot as plt  
from parse_data import parse_log  # Importer la fonction parse_log

def ip_nbPort(dataFrame):
    # Comptage du nombre de ports distincts contactés par chaque adresse IP source (src)
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique()

    # Filtrage : on ne garde que les IP ayant contacté plus de 50 ports distincts
    limit = int(input("Select the minimum number of ports : "))
    port_scan_attempts = port_scan_attempts[port_scan_attempts > limit]
    print(port_scan_attempts)

    # Création du graphique
    port_scan_attempts.plot(kind="bar", color="skyblue", edgecolor="black")

    # Ajout des labels et du titre au graphique
    plt.xlabel("Adresse IP source")  
    plt.ylabel("Nombre de ports distincts contactés")  
    plt.title("Nombre de tentatives de connexion par adresse IP")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  

    # Affichage du graphique
    plt.show()


def ip_connexionTime(dataFrame):
    connexionTime = dataFrame.groupby("src")["duration"].mean()
    limit = int(input("Select the minimum duration : "))
    connexionTime = connexionTime[connexionTime > limit]
    connexionTime.plot(kind="bar", color="skyblue", edgecolor="black")
    plt.xlabel("Adresse IP source")
    plt.ylabel("Durée de connexion")
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  
    plt.show()



if __name__ == '__main__':
    # Utiliser parse_log pour charger les données
    dataFrame = parse_log("data/conn_sample.log")
    ip_connexionTime(dataFrame)
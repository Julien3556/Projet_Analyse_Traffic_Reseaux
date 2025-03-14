# Importation des bibliothèques nécessaires
import pandas as pd
import detect_scan_port
import parse_data
import detect_anomalies
import os

"""
Bibliothèques à installer :
-pandas
-scikit-learn
-pyshark
-matplotlib
"""


# Définition des noms de colonnes
columns = ['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state']

# Fichier par défaut :
file = 'data/conn_sample.log'

# Initialisation d'un dataFrame
# dataFrame = pd.DataFrame()
# print(dataFrame)

"""
Documentation du code

Ce code utilise la structure match-case pour exécuter différentes commandes en fonction de l'entrée utilisateur.

Commandes possibles :
- quitter | q : Permet de quitter le programme en affichant un message de déconnexion.
- afficher : Affiche les premières lignes du DataFrame.
- select : Permet à l'utilisateur de sélectionner un fichier en saisissant son nom.
- detect_scan_port : Effectue un scan de ports sur les données du DataFrame via la classe Scans.
- convert : Convertit les données du fichier sélectionné et affiche un échantillon de 20 lignes.
- http : Détecte les activités HTTP suspectes dans le DataFrame.
- _ : Affiche un message d'erreur si la commande est inconnue.

Dépendances :
- pandas (pd) pour la manipulation des données
- detect_scan_port pour les scans de ports
- parse_data pour la conversion des données

"""

if __name__ == "__main__" :
    while True:
        print("\n===Commandes possibles=== \n\n1-Select file (select) \n2-Afficher les logs (print) \n3-Scans de ports (sp) \n4-Détecte les activités anormales(detect) \n5-Convertisseur de data (convert) \n6-Detection http suspecte (http)")
        commandes = input(">>> : ")
        # if dataFrame.empty:
        #     print("Le dataFrame est vide")
        #     print("Utiliser la commande select pour sélectionner un fichier ou convert pour convertir un fichier pcap")
        match commandes.lower():
            case "quitter" | "q":
                print("Déconnexion réussie")
                break
            
            case "afficher":
                print(dataFrame.head())

            case "select":
                repertoire = "data"
                print("Vous avez tous ces fichiers dans le répertoire data : ")
                
                for fichier in os.listdir(repertoire):
                    if fichier.endswith(".pcap") or fichier.endswith(".log"):
                        print(fichier)
                
                # Création d'un fichier tampon
                buffer_file = input("File name : ")
                buffer_file = "data/" + buffer_file
                
                # Vérification de l'existence du fichier tampon
                if os.path.isfile(buffer_file):
                    file = buffer_file
                    print("Le fichier a bien été pris en compte.")
                else:
                    print("Aucun fichier trouvé dans le dossier \"data\".")

            case "sp":
                dataFrame = parse_data.parse_log(file)
                detect_scan_port.scans(dataFrame)
                
            case "detect":
                dataFrame = parse_data.parse_log(file)
                detect_scan_port.scans(dataFrame)

            case "convert":
                data = parse_data.convert_data(file)
                print(data.sample(20))

            case "http":
                d.detect(dataFrame)
                
            case _ if len(commandes) > 10:
                print("Tout va bien.")

            case _:
                print("Erreur de commande.")

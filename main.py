# Importation des bibliothèques nécessaires
import pandas as pd
import detect_scan_port as sp
import parse_data as pa
import detect_http_suspect as d
import os

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
- sp : Effectue un scan de ports sur les données du DataFrame via la classe Scans.
- sp2 : Effectue une autre version du scan de ports.
- convert : Convertit les données du fichier sélectionné et affiche un échantillon de 20 lignes.
- http : Détecte les activités HTTP suspectes dans le DataFrame.
- _ : Affiche un message d'erreur si la commande est inconnue.

Dépendances :
- pandas (pd) pour la manipulation des données
- sp pour les scans de ports
- pa pour la conversion des données
- d pour la détection HTTP

"""

if __name__ == "__main__" :
    while True:
        print("\n===Commandes possibles=== \n\n1-Select file (select) \n2-Afficher les logs (print) \n3-Scans de ports (sp) \n \n5-Convertisseur de data (convert) \n6-Detection http suspecte (http)")
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
                    print("Le fichier n'existe pas.")

            case "sp":
                # Charger les logs dans un DataFrame
                dataFrame = pd.read_csv(file, sep="\s+", names=columns, engine="python")
                # Correction du format timestamp
                dataFrame['timestamp'] = pd.to_datetime(dataFrame['timestamp'].astype(float), unit='s')
                sp.scans(dataFrame)

            case "convert":
                data = pa.convert_data(file)
                print(data.sample(20))

            case "http":
                d.detect(dataFrame)
                
            case _ if len(commandes) > 10:
                print("Tout va bien.")

            case _:
                print("Erreur de commande.")

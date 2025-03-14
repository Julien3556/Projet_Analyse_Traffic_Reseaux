# Importation des bibliothèques nécessaires
import pandas as pd
import detect_scan_port
import parse_data
import detect_anomalies
import basic_stat
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
- detect_anomalies pour la détection d'anomalies
- basic_stat pour la crétion de graphique
- os pour la gestion de fichier

"""

if __name__ == "__main__" :
    while True:
        print("\n===Commandes possibles=== \n\n0-Quit \n1-Select file (select) \n2-Afficher les logs (print) \n3-Convertisseur de data (convert) \n4-Scans de ports (sp) \n5-Détecte les activités anormales (detect)  \n6-eeStatee (stat) \n7-Modèle Isolation Forest (forest) ")
        commandes = input(">>> : ")
        # if dataFrame.empty:
        #     print("Le dataFrame est vide")
        #     print("Utiliser la commande select pour sélectionner un fichier ou convert pour convertir un fichier pcap")
        match commandes.lower():
            case "quit" | "q":
                print("Déconnexion réussie.")
                break
            
            case "print":
                try :
                    print(dataFrame.head())
                except:
                    print('Ulitilser la commande convert pour créer un dataFrame.')

            case "select":
                repertoire = "data"
                print("Vous avez tous ces fichiers dans le répertoire data : ")
                
                for fichier in os.listdir(repertoire):
                    if fichier.endswith(".pcap") or fichier.endswith(".log"):
                        print(fichier)
                
                # Création d'un fichier tampon
                buffer_file = input("Nom du fichier : ")
                buffer_file = "data/" + buffer_file
                
                # Vérification de l'existence du fichier tampon
                if os.path.isfile(buffer_file):
                    file = buffer_file
                    print("Le fichier ",file,"a bien été pris en compte.")
                else:
                    print("Aucun fichier trouvé dans le dossier \"data\".")

            case "sp":
                dataFrame = parse_data.parse_log(file)
                detect_scan_port.scans(dataFrame)
                
            case "detect":
                protos = ['tcp','udp'] # Cf parsa data
                proto = input("Protocole à analyser : ").lower().strip()

                # Vérification que le protocole est bien dans la liste autorisée
                if proto in protos:
                    print(f"✅ Le protocole choisi est correct : {proto}")
                    anomalies = detect_anomalies.detect_anomalies(data, 'length', filter=f'proto == "{proto}"')
                    print(anomalies)
                else:
                    print(f"❌ Erreur : Le protocole '{proto}' n'est pas valide. Protocole(s) disponible(s) : {', '.join(protos)}")
                data = parse_data.convert_data('data/conn_sample.log')

                print("Le protocole choisit est correct.")
                anomalies = detect_anomalies.detect_anomalies(data, 'length', filter='proto == "'+str(proto)+'"')
                print(anomalies)

            case "convert":
                dataFrame = parse_data.convert_data(file)
                print(dataFrame.sample(20))
                print("Le fichier ",file,"a bien été convertit.")

            case "stat":
                dataFrame = parse_data.parse_log(file)
                print("Création du graphique en cours...")
                basic_stat.ip_nbPort(dataFrame)
                
            case "forest":
                data = convert_data(file)
                model = train_isolation_forest(data, ['length', 'src_port', 'dst_port'])
                anomalies = detect_anomalies(model, data, ['length', 'src_port', 'dst_port'])
                print(anomalies)
                
            case _ if len(commandes) > 10:
                print("Erreur d'utilisation de commande : ne rentrer pas d'arguments")

            case _:
                print("Erreur de commande.")

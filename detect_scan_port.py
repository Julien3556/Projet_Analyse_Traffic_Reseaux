# Importation des bibliothèques nécessaires
import pandas as pd
from parse_data import parse_log

def scans(dataFrame, threshold=50):
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique() # Tableau qui comprend un grand nb de connexions
    suspected_scanners = port_scan_attempts[port_scan_attempts > threshold]

    if not suspected_scanners.empty:
        print("Détection de scans de ports suspects :")
        print(suspected_scanners)
        print("\n")
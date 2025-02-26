import pandas as pd

# Vérifier la présence des colonnes
def detect(dataFrame):
    if "service" in dataFrame.columns and "orig_bytes" in dataFrame.columns:
        # Convertir la colonne "orig_bytes" en numérique (forcera les erreurs en NaN)
        dataFrame["orig_bytes"] = pd.to_numeric(dataFrame["orig_bytes"], errors="coerce")
        
        # Filtrer les requêtes HTTP avec un volume anormalement élevé
        http_anomalies = dataFrame[(dataFrame["service"] == "http") & 
                                (dataFrame["orig_bytes"].fillna(0) > 10000)]
        
        print("\n⚠️  ANOMALIES HTTP DETECTÉES ⚠️")
        print("Nombre d'anomalies détectées :", len(http_anomalies))
        
        if not http_anomalies.empty:
            print("\nDétails des anomalies :\n", http_anomalies)
        else:
            print("\nAucun comportement anormal détecté.")
    else:
        print("Erreur : Colonnes manquantes dans le DataFrame.")
        
if __name__ == '__main__':
    detect(dataFrame)
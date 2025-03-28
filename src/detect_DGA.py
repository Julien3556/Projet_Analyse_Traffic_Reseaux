import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import parse_data

# Fonction pour extraire des caractéristiques d'un domaine
def extract_features(domain):
    if pd.isna(domain) or domain == "(empty)":
        return {"length": 0, "num_digits": 0, "num_hyphens": 0, "entropy": 0}
    
    return {
        "length": len(domain),
        "num_digits": sum(c.isdigit() for c in domain),
        "num_hyphens": domain.count("-"),
        "entropy": -sum(p * np.log2(p) for p in np.bincount(list(map(ord, domain)), minlength=256) / len(domain) if p > 0)
    }

file = 'data/conn_sample.log'
# Charger un dataset avec gestion de l'encodage
try:
    dataFrame = pd.read_csv(file, sep="\t", header=None, encoding="ISO-8859-1", 
                            names=['timestamp', 'uid', 'src', 'src_port', 'dst', 'dst_port', 'proto', 'service', 
                                   'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 
                                   'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'DNS'])
except UnicodeDecodeError:
    print("Erreur d'encodage lors de la lecture du fichier.")
    exit()

# Vérifier l'existence de la colonne 'DNS'
if 'DNS' not in dataFrame.columns:
    print("La colonne 'DNS' est absente du fichier.")
    exit()

# Transformation des domaines en features
dns_features = pd.DataFrame([extract_features(domain) for domain in dataFrame['DNS']])
X = dns_features

# Génération de labels fictifs (1 pour DGA, 0 pour normal) avec une longueur correcte
y = np.random.randint(0, 2, size=len(X))

# Séparation des données
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Entraînement du modèle
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Prédiction et évaluation
y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))

# Sauvegarde du modèle
joblib.dump(clf, "dga_detector.pkl")

# Fonction de détection en temps réel
def detect_dga(df, model_path="dga_detector.pkl"):
    clf = joblib.load(model_path)
    features = pd.DataFrame([extract_features(domain) for domain in df['DNS']])
    predictions = clf.predict(features)
    df['DGA_detected'] = predictions
    return df

# Exemple d'utilisation
new_data = dataFrame[['DNS']].dropna().reset_index(drop=True)
print(new_data)
detected = detect_dga(new_data)
print(detected)

# file = 'data/sample.pcap'
# # Charger un dataset 
# dataFrame = parse_data.parse_log(file)
# print("test")
# print(dataFrame['DNS'].to_string()) 
# # Supprime les lignes où DNS est NaN/None
# dataFrame = dataFrame.dropna(subset=['DNS'])  
# if dataFrame.empty:
#     print("ERREUR : dataFrame est vide après le nettoyage. Vérifiez le fichier d'entrée !")
#     exit()

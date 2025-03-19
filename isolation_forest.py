import pandas as pd
from sklearn.ensemble import IsolationForest
from parse_data import convert_data
import pickle

def train_isolation_forest(data, features):
    """
    Entraîne un modèle Isolation Forest pour détecter les anomalies.

    Args:
        data (pd.DataFrame): Le DataFrame contenant les données à analyser.
        features (list): La liste des colonnes à utiliser pour l'entraînement.

    Returns:
        IsolationForest: Le modèle Isolation Forest entraîné.
    """
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(data[features])
    return model

def detect_anomalies(model, data, features):
    """
    Détecte les anomalies dans les données en utilisant le modèle entraîné.

    Args:
        model (IsolationForest): Le modèle Isolation Forest entraîné.
        data (pd.DataFrame): Le DataFrame contenant les données à analyser.
        features (list): La liste des colonnes à utiliser pour la détection.

    Returns:
        pd.DataFrame: Un DataFrame contenant les lignes avec des activités anormales.
    """
    data['anomaly'] = model.predict(data[features])
    anomalies = data[data['anomaly'] == -1]

    return anomalies

def load_model(filename):
    """
    Charge un modèle Isolation Forest à partir d'un fichier pickle.

    Args:
        filename (str): Le nom du fichier contenant le modèle sauvegardé.

    Returns:
        IsolationForest: Le modèle Isolation Forest chargé.
    """
    with open(filename, "rb") as file:
        model = pickle.load(file)
    return model

if __name__ == '__main__':
    data = convert_data('data/conn_sample.log')
    model = train_isolation_forest(data, ['length', 'src_port', 'dst_port'])
    with open('.\data\isolation_forest_model.pkl', 'wb') as file:
        pickle.dump(model, file)
    anomalies = detect_anomalies(model, data, ['length', 'src_port', 'dst_port'])
    print(anomalies)
import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

def train_isolation_forest(data, features):
    """
    Trains an Isolation Forest model to detect anomalies.

    Arguments:
        - data (pd.DataFrame): The DataFrame containing the data to analyze.
        - features (list): The list of columns to use for training.

    Functionality:
        - Initializes an Isolation Forest model with a contamination rate of 0.01.
        - Fits the model to the specified features in the data.

    Returns:
        - IsolationForest: The trained Isolation Forest model.
    """
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(data[features])
    return model

def detect_anomalies(model, data, features):
    """
    Detects anomalies in the data using a trained Isolation Forest model.

    Arguments:
        - model (IsolationForest): The trained Isolation Forest model.
        - data (pd.DataFrame): The DataFrame containing the data to analyze.
        - features (list): The list of columns to use for anomaly detection.

    Functionality:
        - Predicts anomalies in the data using the trained model.
        - Adds an 'anomaly' column to the DataFrame where -1 indicates an anomaly.
        - Filters and returns rows with anomalous activities.

    Returns:
        - pd.DataFrame: A DataFrame containing rows with anomalous activities.
    """
    data['anomaly'] = model.predict(data[features])
    anomalies = data[data['anomaly'] == -1]
    return anomalies

def load_model(filename):
    """
    Loads an Isolation Forest model from a pickle file.

    Arguments:
        - filename (str): The name of the file containing the saved model.

    Functionality:
        - Opens the specified pickle file and loads the Isolation Forest model.

    Returns:
        - IsolationForest: The loaded Isolation Forest model.
    """
    with open(filename, "rb") as file:
        model = pickle.load(file)
    return model

if __name__ == '__main__':
    """
    Main function to train and test the Isolation Forest model.

    Functionality:
        - Loads network traffic data using the `convert_data` function.
        - Trains an Isolation Forest model on specified features.
        - Saves the trained model to a pickle file.
        - Detects anomalies in the data using the trained model.
        - Prints the detected anomalies.
    """
    from parse_data import convert_data  # Import convert_data function

    # Load data
    data = convert_data('data/conn_sample.log')

    # Train the Isolation Forest model
    model = train_isolation_forest(data, ['length', 'src_port', 'dst_port'])

    # Save the trained model
    with open("isolation_forest_model.pkl", "wb") as file:
        pickle.dump(model, file)

    # Detect anomalies
    anomalies = detect_anomalies(model, data, ['length', 'src_port', 'dst_port'])
    print("Detected anomalies:")
    print(anomalies)
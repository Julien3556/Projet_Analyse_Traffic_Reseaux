import pandas as pd
import random
import string
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

def run_DGA_detection(dataFrame, file_name, view=False):
    """
    Detects Domain Generation Algorithm (DGA) domains in a given dataset.

    Parameters:
        dataFrame (pd.DataFrame): The input DataFrame containing DNS data.
        file_name (str): The name of the file to save detection results.
        view (bool): If True, prints detailed detection results to the console.

    Returns:
        None
    """
    # === 1. GÉNÉRER UN JEU DE DONNÉES SIMULÉ ===
    # Generate a simulated dataset of legitimate and DGA domains.

    # Examples of legitimate domains
    legit_domains = [
        "google.com", "facebook.com", "amazon.com", "wikipedia.org", "youtube.com",
        "openai.com", "github.com", "linkedin.com", "microsoft.com", "apple.com"
    ]

    # Function to generate random DGA-like domains
    def generate_dga_domain():
        """
        Generates a random DGA-like domain.

        Returns:
            str: A randomly generated domain name.
        """
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(10, 25))) + ".xyz"

    # Generate 100 random DGA domains
    dga_domains = [generate_dga_domain() for _ in range(100)]
    legit_domains_extended = legit_domains * 10  # Balance the classes by repeating legitimate domains

    # Combine legitimate and DGA domains into a single dataset
    all_domains = dga_domains + legit_domains_extended
    labels = [1] * len(dga_domains) + [0] * len(legit_domains_extended)  # 1 = DGA, 0 = legitimate

    # === 2. EXTRAIRE DES CARACTÉRISTIQUES ===
    # Extract features from domain names for classification.

    def extract_features(domain):
        """
        Extracts features from a domain name.

        Parameters:
            domain (str): The domain name to extract features from.

        Returns:
            list: A list of extracted features [length, num_digits, num_consonants, num_vowels, entropy].
        """
        domain = domain.split('.')[0]  # Remove the TLD (e.g., ".com")
        length = len(domain)
        num_digits = sum(c.isdigit() for c in domain)
        num_consonants = sum(c in "bcdfghjklmnpqrstvwxyz" for c in domain.lower())
        num_vowels = sum(c in "aeiou" for c in domain.lower())
        entropy = -sum((domain.count(c) / length) * np.log2(domain.count(c) / length) for c in set(domain))
        return [length, num_digits, num_consonants, num_vowels, entropy]

    # Extract features for all domains
    features_X = [extract_features(d) for d in all_domains]

    # === 3. ENTRAÎNER LE MODÈLE ===
    # Train a Random Forest classifier on the extracted features.

    X_train, X_test, y_train, y_test = train_test_split(features_X, labels, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    print("=== ÉVALUATION DU MODÈLE ===")
    print(classification_report(y_test, clf.predict(X_test)))

    # === 4. TESTER UN DOMAINE PERSONNALISÉ ===
    # Detect individual domains and log results.

    detection_logs = []  # List to store detection results

    def log_detection(domain, ip, is_dga, confidence):
        """
        Logs the detection result for a domain.

        Parameters:
            domain (str): The domain name.
            ip (str): The IP address associated with the domain.
            is_dga (int): 1 if the domain is DGA, 0 otherwise.
            confidence (float): The confidence score of the prediction.

        Returns:
            None
        """
        detection_logs.append({
            'domain': domain,
            'ip': ip,
            'is_dga': is_dga,
            'confidence': round(confidence, 2)
        })

    def detect_domain(domain, ip):
        """
        Detects whether a domain is DGA or legitimate.

        Parameters:
            domain (str): The domain name to detect.
            ip (str): The IP address associated with the domain.

        Returns:
            None
        """
        feat = extract_features(domain)
        prediction = clf.predict([feat])[0]
        proba = clf.predict_proba([feat])[0][prediction]

        # Log the result
        log_detection(domain, ip, int(prediction), proba)

        if view:
            if prediction == 1:
                print(f"⚠️ DGA domain detected: {domain} IP : {ip} (confidence : {proba:.2f})")
            else:
                print(f"✅ Normal domain : {domain} IP : {ip} (confidence : {proba:.2f})")

    # === 5. PARCOURIR LE DATAFRAME ===
    # Process the input DataFrame and detect domains.

    # Drop rows with missing or empty 'DNS' values
    dataFrame = dataFrame.dropna(subset=['DNS'])
    dataFrame = dataFrame[dataFrame['DNS'].str.strip() != ""]
    print(dataFrame.head())

    # Iterate through the DataFrame and detect domains
    if view:
        print("=== Domains ===")
    else:
        print("File creation...")

    for index, row in dataFrame.iterrows():
        domaine = row['DNS']  # Change between 'DNS' or 'domain' as needed
        ip = row['src']  # Change between 'src' or other column as needed
        detect_domain(domaine, ip)

    # === 6. SAUVEGARDE DES RÉSULTATS ===
    # Save detection results to a CSV file.

    results_df = pd.DataFrame(detection_logs)
    new_file_name = "data/detection_results_dns_" + file_name[5:]
    results_df.to_csv(new_file_name, index=False)
    print("Results saved in '", new_file_name, "'")
import pandas as pd
import parse_data as parse_data
import random
import string
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

# === 1. GÉNÉRER UN JEU DE DONNÉES SIMULÉ ===

# Exemples de domaines légitimes
legit_domains = [
    "google.com", "facebook.com", "amazon.com", "wikipedia.org", "youtube.com",
    "openai.com", "github.com", "linkedin.com", "microsoft.com", "apple.com"
]

# Générer des domaines DGA aléatoires
def generate_dga_domain():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(10, 25))) + ".xyz"

dga_domains = [generate_dga_domain() for _ in range(100)]
legit_domains_extended = legit_domains * 10  # Pour équilibrer les classes

all_domains = dga_domains + legit_domains_extended
labels = [1]*len(dga_domains) + [0]*len(legit_domains_extended)  # 1 = DGA, 0 = légitime

# === 2. EXTRAIRE DES CARACTÉRISTIQUES ===

def extract_features(domain):
    domain = domain.split('.')[0]  # enlever le TLD (ex: ".com")
    length = len(domain)
    num_digits = sum(c.isdigit() for c in domain)
    num_consonants = sum(c in "bcdfghjklmnpqrstvwxyz" for c in domain.lower())
    num_vowels = sum(c in "aeiou" for c in domain.lower())
    entropy = -sum((domain.count(c)/length) * np.log2(domain.count(c)/length) for c in set(domain))
    return [length, num_digits, num_consonants, num_vowels, entropy]

features_X = [extract_features(d) for d in all_domains]

# === 3. ENTRAÎNER LE MODÈLE ===

X_train, X_test, y_train, y_test = train_test_split(features_X, labels, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

print("=== ÉVALUATION DU MODÈLE ===")
print(classification_report(y_test, clf.predict(X_test)))

# === 4. TESTER UN DOMAINE PERSONNALISÉ ===

def detect_domain(domain):
    feat = extract_features(domain)
    prediction = clf.predict([feat])[0]
    proba = clf.predict_proba([feat])[0][prediction]
    if prediction == 1:
        print(f"⚠️ Domaine DGA détecté : {domain} (confiance : {proba:.2f})")
    else:
        print(f"✅ Domaine normal : {domain} (confiance : {proba:.2f})")

# # === 5. EXEMPLE D’UTILISATION ===
# while True:
#     test_domain = input("Entrez un nom de domaine à tester (ou 'exit') : ")
#     if test_domain.lower() == "exit":
#         break
#     detect_domain(test_domain)
    
# === 1. Exemple de DataFrame avec une colonne 'DNS' ===
dataFrame = pd.read_csv("data/sample.csv")

dataFrame = dataFrame.dropna(subset=['DNS'])  # Supprime les valeurs NaN
dataFrame = dataFrame[dataFrame['DNS'].str.strip() != ""]  # Supprime les valeurs vides ("")
print(dataFrame.head())
# === 2. Parcourir la colonne 'DNS' ===
print("=== Parcours des domaines ===")
for index, row in dataFrame.iterrows():
    domaine = row['DNS'] # A changer entre DNS ou domain
    detect_domain(domaine)
    
    

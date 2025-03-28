def detect_anomalies(data, column, threshold=None, filter=None):
    """
    Détecte les activités anormales basées sur une colonne et un seuil.

    Args:
        data (pd.DataFrame): Le DataFrame contenant les données à analyser.
        column (str): Le nom de la colonne à analyser.
        threshold (int, optionnel): Le seuil au-dessus duquel une activité est considérée comme anormale.
                                    Si non fourni, il est par défaut la moyenne plus trois écarts-types de la colonne.

    Returns:
        pd.DataFrame: Un DataFrame contenant les lignes avec des activités anormales.
    """
    if threshold is None:
        threshold = data[column].mean() + 3 * data[column].std()
    if filter is not None:
        data = data.query(filter)
    anomalies = data[data[column] > threshold]
    return anomalies


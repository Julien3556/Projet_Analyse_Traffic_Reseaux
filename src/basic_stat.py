# Import necessary libraries
import pandas as pd  
import matplotlib.pyplot as plt  
from src.parse_data import parse_log  # Import the parse_log function
from src.isolation_forest import detect_anomalies, load_model  # Import the detect_anomalies function

def ip_nbPort(dataFrame, limit):
    """
    Analyzes the number of distinct ports contacted by each source IP address.

    Arguments:
        - dataFrame: pandas.DataFrame containing network traffic data.

    Functionality:
        - Groups data by source IP address and counts the number of distinct destination ports.
        - Filters IPs that contacted more than a user-specified number of ports.
        - Displays a bar chart of the results.

    Returns:
        - None
    """
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique()
    port_scan_attempts = port_scan_attempts[port_scan_attempts > limit]
    print(port_scan_attempts)

    port_scan_attempts.plot(kind="bar", color="skyblue", edgecolor="black")
    plt.xlabel("Source IP address") 
    plt.ylabel("Number of distinct ports contacted")  
    plt.title("Number of connection attempts per IP address")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  
    plt.show()


def ip_connexionTime(dataFrame, limit):
    """
    Analyzes the maximum connection duration for each source IP address.

    Arguments:
        - dataFrame: pandas.DataFrame containing network traffic data.

    Functionality:
        - Groups data by source IP address and calculates the maximum connection duration.
        - Filters IPs with a maximum duration greater than a user-specified value.
        - Displays a bar chart of the results.

    Returns:
        - None
    """
    connexionTime = dataFrame.groupby("src")["duration"].max()
    connexionTime = connexionTime[connexionTime > limit]

    connexionTime.plot(kind="bar", color="skyblue", edgecolor="black")
    plt.xlabel("Source IP address")
    plt.ylabel("Maximum connection duration")
    plt.title("Connection duration per IP address")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  
    plt.show()


def destPort_nbConnexion(dataFrame, limit):
    """
    Analyzes the number of connections to each destination port.

    Arguments:
        - dataFrame: pandas.DataFrame containing network traffic data.

    Functionality:
        - Groups data by destination port and counts the number of connections.
        - Filters ports with more connections than a user-specified threshold.
        - Displays a bar chart of the results.

    Returns:
        - None
    """
    port_connexions = dataFrame.groupby("dst_port").size()
    port_connexions = port_connexions[port_connexions > limit]

    port_connexions.plot(kind="bar", color="skyblue", edgecolor="black")
    plt.xlabel("Destination port")  
    plt.ylabel("Number of connections")  
    plt.title("Number of connections per destination port")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  
    plt.show()


def maxLength_ip(dataFrame, limit):
    """
    Analyzes the maximum packet size transmitted by each source IP address.

    Arguments:
        - dataFrame: pandas.DataFrame containing network traffic data.

    Functionality:
        - Groups data by source IP address and calculates the maximum packet size.
        - Filters IPs with a maximum packet size below a user-specified threshold.
        - Displays a bar chart of the results.

    Returns:
        - None
    """
    ip_connexions = dataFrame.groupby("src")["length"].max()
    ip_connexions = ip_connexions[ip_connexions < limit]

    ip_connexions.plot(kind="bar", color="skyblue", edgecolor="black")
    plt.xlabel("IP of packet's transmitter")  
    plt.ylabel("Maximum size of transmitted packets")  
    plt.title("Maximum packet size per user")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  
    plt.show()


if __name__ == '__main__':
    """
    Main function to analyze network traffic data.

    Functionality:
        - Loads network traffic data using the `parse_log` function.
        - Detects anomalies using a pre-trained isolation forest model.
        - Calls analysis functions to generate statistics and visualizations.
    """
    dataFrame = parse_log("data/conn_sample.log")
    dataFrameWhenAnomalies = detect_anomalies(load_model(".\data\isolation_forest_model.pkl"), dataFrame, ['length', 'src_port', 'dst_port'])
    destPort_nbConnexion(dataFrame)
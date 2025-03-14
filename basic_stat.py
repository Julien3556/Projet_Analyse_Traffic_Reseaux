# Import necessary libraries
import pandas as pd  
import matplotlib.pyplot as plt  
from parse_data import parse_log  # Import the parse_log function

def ip_nbPort(dataFrame):
    # Count the number of distinct ports contacted by each source IP address (src)
    port_scan_attempts = dataFrame.groupby("src")["dst_port"].nunique()

    # Filter: keep only IPs that contacted more than a specified number of distinct ports
    limit = int(input("Select the minimum number of ports : "))
    port_scan_attempts = port_scan_attempts[port_scan_attempts > limit]
    print(port_scan_attempts)

    # Create the chart
    port_scan_attempts.plot(kind="bar", color="skyblue", edgecolor="black")

    # Add labels and title to the chart
    plt.xlabel("Source IP address")  
    plt.ylabel("Number of distinct ports contacted")  
    plt.title("Number of connection attempts per IP address")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  

    # Display the chart
    plt.show()


def ip_connexionTime(dataFrame):
    connexionTime = dataFrame.groupby("src")["duration"].max()

    # Filter: keep only IPs that the average connection duration is greater than a specified value
    limit = float(input("Select the minimum duration : "))
    connexionTime = connexionTime[connexionTime > limit]

    # Create the chart
    connexionTime.plot(kind="bar", color="skyblue", edgecolor="black")

    # Add labels and title to the chart
    plt.xlabel("Source IP address")
    plt.ylabel("Maximum connection duration")
    plt.title("Connection duration per IP address")  
    plt.xticks(rotation=45, fontsize=6)  
    plt.grid(axis="y", linestyle="--", alpha=0.7)  
    plt.show()


if __name__ == '__main__':
    # Use parse_log to load the data
    dataFrame = parse_log("data/conn_sample.log")
    ip_connexionTime(dataFrame)
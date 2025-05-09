import pandas as pd
import src.detect_scan_port as detect_scan_port
import src.parse_data as parse_data
import src.detect_anomalies as detect_anomalies
import src.basic_stat as basic_stat
import src.isolation_forest as isolation_forest
import os

"""
Libraries to install:
- pandas
- scikit-learn
- pyshark
- matplotlib
"""

# Define column names
# columns = ['src', 'dst', 'proto', 'length', 'timestamp', 'src_port', 'dst_port', 'conn_state']

# Default file:
file = 'data/conn_sample.log'

# Initialize a DataFrame
dataFrame = pd.DataFrame()
# print(dataFrame)

"""
Code Documentation

This code uses a match-case structure to execute different commands based on user input.

Available commands:
- quit | q: Exits the program and displays a logout message.
- show: Displays the first lines of the DataFrame.
- select: Allows the user to select a file by typing its name.
- detect_scan_port: Performs a port scan on the DataFrame data via the Scans class.
- convert: Converts the selected file's data and displays a 20-row sample.
- http: Detects suspicious HTTP activity in the DataFrame.1
- _: Displays an error message if the command is unknown.

Dependencies:
- pandas (pd) for data handling
- detect_scan_port for port scans
- parse_data for data conversion
- detect_anomalies for anomaly detection
- basic_stat for statistics and graph generation
- os for file handling
"""

def stats(dataFrame):
    while True:
        print("Select the statistics to generate: \n0 - Quit \n1 - Number of distinct ports contacted by each source IP address \n2 - Maximum connection duration per source IP address \n3 - Number of connections to each destination port \n4 - Maxium size above all the packet transmitted per user\n")
        choice = input(">>> : ")
        match choice :
            case "q" | "0":
                print("Disconnected.")
                break
            case "1":
                limit = int(input("Select the minimum number of ports : "))
                basic_stat.ip_nbPort(dataFrame,limit)
            case "2":
                limit = int(input("Select the minimum duration : "))
                basic_stat.ip_connexionTime(dataFrame,limit)
            case "3":
                limit = int(input("Select the minimum number of connections : "))
                basic_stat.destPort_nbConnexion(dataFrame,limit)
            case "4":
                limit = int(input("Select the minimum packets's size (bytes): "))
                basic_stat.maxLength_ip(dataFrame,limit)
            case _:
                print("Invalid choice. Please try again.")




if __name__ == "__main__":
    if dataFrame.empty:
        print("The DataFrame is empty.")
        print("Use the 'select' command.")

            
def select():
    folder = "data"
    print("Available files in the 'data' folder:")
    for f in os.listdir(folder):
        if f.endswith(".pcap") or f.endswith(".log") or f.endswith(".csv"):
            print(f)
    
    buffer_file = input("Enter file name: ")
    buffer_file = "data/" + buffer_file

    if (os.path.isfile(buffer_file) and os.listdir(folder) ) and (buffer_file.endswith(".pcap") or buffer_file.endswith(".log") or buffer_file.endswith(".csv")):
        file = buffer_file
        print("File", file, "has been successfully selected.")
    else:
        print("No file found in the 'data' folder.")
        
    if file.endswith(".pcap") or file.endswith(".log"):
        try :
            dataFrame = parse_data.convert_data(file)
            print(dataFrame.sample(20))
            print("File", file, "was successfully converted.")
            if file.endswith(".pcap"):
                file = file[:-4] + ".csv"
            elif file.endswith(".log"):
                file = file[:-3] + ".csv"
        except :
            print("File conversion error.")
    elif file.endswith(".csv"):
        dataFrame = pd.read_csv(file)
    else :
        print("Error in def select")
    return dataFrame

def detect(dataFrame):
    try:
        protocols = ['icmp', 'igmp', 'tcp', 'udp', 'ipv6', 'gre','esp','ah','icmpv6','ospf','sctp','mpls-in-ip']
        print("Differents protocols : ")
        for proto in protocols:
            print("",proto, end='') 
        print("")
        proto = input("Protocol to analyze: ").lower().strip()
        data = parse_data.convert_data(file)

        if proto in protocols:
            print(f"✅ Protocol selected: {proto}")
            anomalies = detect_anomalies.detect_anomalies(data, 'length', filter=f'proto == \"{proto}\"')
            print(anomalies)
        else:
            print(f"❌ Error: Protocol '{proto}' is invalid. Available protocols: {', '.join(protocols)}")
    except:
        print("Error in detect_scan_port")

def forest(dataFrame):
    try:
        model = train_isolation_forest(dataFrame, ['length', 'src_port', 'dst_port'])
        anomalies = detect_anomalies(model, dataFrame, ['length', 'src_port', 'dst_port'])
        print(anomalies)
    except:
        print("Error in isolation forest")

if __name__ == "__main__":
    if dataFrame.empty:
        print("The DataFrame is empty.")
        print("Use the 'select' command.")
    while True:
        print("\n===Available Commands=== \n\n0 - Quit \n1 - Select a file \n2 - Show logs \n3 - Port scans \n4 - Detect anomalies \n5 - Generate statistics \n6 - Isolation Forest Model \n7 - Complete scans")
        command = input(">>> : ")
        match command.lower():
            case "q" | "0":
                print("Successfully disconnected.")
                break
            
            case "1":  # Select
                try:
                    dataFrame=select()
                except:
                    print("Error in select")

            case "2":  # Show
                if dataFrame.empty:
                    print("The DataFrame is empty.")
                    print("Use the 'select' command.")
                    continue
                try:
                    print(dataFrame.head())
                except:
                    print("Use the 'select' command to create a DataFrame first.")

            case "3":  # Port scans
                if dataFrame.empty:
                    print("The DataFrame is empty.")
                    print("Use the 'select' command.")
                    continue
                try:
                    imput = int(input("Select the threshold : "))
                    detect_scan_port.scans(dataFrame, imput)
                except:
                    print("Error in detect_scan_port")

            case "4":  # Detect anomalies
                if dataFrame.empty:
                    print("The DataFrame is empty.")
                    print("Use the 'select' command.")
                    continue
                detect(dataFrame)

            case "5":  # Statistics
                if dataFrame.empty:
                    print("The DataFrame is empty.")
                    print("Use the 'select' command.")
                    continue          
                stats(dataFrame)

            case "6":  # Isolation Forest
                if dataFrame.empty:
                    print("The DataFrame is empty.")
                    print("Use the 'select' command.")
                    continue
                forest(dataFrame)
                
            case "7":  # Complete scans
                if dataFrame.empty:
                    print("The DataFrame is empty.")
                    print("Use the 'select' command.")
                    continue
                
                print("\nPort scans")
                imput = int(input("Select the threshold : "))
                detect_scan_port.scans(dataFrame, imput)
                
                print("\nDetect anomalies")
                detect(dataFrame)
                
                condition = input("Do you want to do Isolation Forest ? (y/N):")
                if condition == "y":
                    print("\nIsolation Forest")
                    forest(dataFrame)
                    
                print("\nStatistics")
                stats(dataFrame)

            case _:
                print("Unknown command.")




# Import necessary libraries
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
# dataFrame = pd.DataFrame()
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
- http: Detects suspicious HTTP activity in the DataFrame.
- _: Displays an error message if the command is unknown.

Dependencies:
- pandas (pd) for data handling
- detect_scan_port for port scans
- parse_data for data conversion
- detect_anomalies for anomaly detection
- basic_stat for statistics and graph generation
- os for file handling
"""

if __name__ == "__main__":
    while True:
        print("\n===Available Commands=== \n\n0 - Quit \n1 - Select a file \n2 - Show logs \n3 - Data converter \n4 - Port scans \n5 - Detect anomalies \n6 - Generate statistics \n7 - Isolation Forest Model \n8 - Complete scans")
        command = input(">>> : ")
        # if dataFrame.empty:
        #     print("The DataFrame is empty.")
        #     print("Use the 'select' command to choose a file or 'convert' to convert a pcap file.")
        match command.lower():
            case "q" | "0":
                print("Successfully disconnected.")
                break

            case "2":  # Show
                try:
                    print(dataFrame.head())
                except:
                    print("Use the 'convert' command to create a DataFrame first.")

            case "1":  # Select
                folder = "data"
                print("Available files in the 'data' folder:")
                for f in os.listdir(folder):
                    if f.endswith(".pcap") or f.endswith(".log"):
                        print(f)
                
                buffer_file = input("Enter file name: ")
                buffer_file = "data/" + buffer_file

                if os.path.isfile(buffer_file):
                    file = buffer_file
                    print("File", file, "has been successfully selected.")
                else:
                    print("No file found in the 'data' folder.")

            case "4":  # Port scans
                dataFrame = parse_data.parse_log(file)
                detect_scan_port.scans(dataFrame)

            case "5":  # Detect anomalies
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

            case "3":  # Convert
                dataFrame = parse_data.convert_data(file)
                print(dataFrame.sample(20))
                print("File", file, "was successfully converted.")

            case "6":  # Statistics
                dataFrame = parse_data.parse_log(file)
                basic_stat.ip_nbPort(dataFrame)

            case "7":  # Isolation Forest
                dataFrame = parse_data.convert_data(file)
                model = train_isolation_forest(dataFrame, ['length', 'src_port', 'dst_port'])
                anomalies = detect_anomalies(model, dataFrame, ['length', 'src_port', 'dst_port'])
                print(anomalies)
                
            case "8":  # Complete scans
                dataFrame = parse_data.convert_data(file)
                
                print("\nPort scans")
                detect_scan_port.scans(dataFrame)
                
                print("\nDetect anomalies")
                protocols = ['icmp', 'igmp', 'tcp', 'udp', 'ipv6', 'gre','esp','ah','icmpv6','ospf','sctp','mpls-in-ip']
                print("Differents protocols : ")
                for proto in protocols:
                    print("",proto, end='') 
                print("")
                proto = input("\nProtocol to analyze: ").lower().strip()
                data = parse_data.convert_data(file)
                if proto in protocols:
                    print(f"✅ Protocol selected: {proto}")
                    anomalies = detect_anomalies.detect_anomalies(data, 'length', filter=f'proto == \"{proto}\"')
                    print(anomalies)
                else:
                    print(f"❌ Error: Protocol '{proto}' is invalid. Available protocols: {', '.join(protocols)}")
                
                condition = input("Do you want to do Isolation Forest ? (y/N):")
                if condition == "y":
                    print("\nIsolation Forest")
                    model = train_isolation_forest(dataFrame, ['length', 'src_port', 'dst_port'])
                    anomalies = detect_anomalies(model, dataFrame, ['length', 'src_port', 'dst_port'])
                    print(anomalies)
                    
                print("\nStatistics")
                basic_stat.ip_nbPort(dataFrame)
                


            case _ if len(command) > 10:
                print("Command input too long. Please try again.")

            case _:
                print("Unknown command.")

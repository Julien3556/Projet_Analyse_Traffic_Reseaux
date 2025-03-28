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
    choice = int(input("Select the statistics to generate: \n1 - Number of distinct ports contacted by each source IP address \n2 - Maximum connection duration per source IP address \n3 - Number of connections to each destination port \n4 - Maxium size above all the packet transmitted per user>>> : "))
    match choice :
        case 1:
            basic_stat.ip_nbPort(dataFrame)
        case 2:
            basic_stat.ip_connexionTime(dataFrame)
        case 3:
            basic_stat.destPort_nbConnexion(dataFrame)
        case 4:
            basic_stat.maxLength_ip(dataFrame)
        case _:
            print("Invalid choice. Please try again.")




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
                    print("Error")

            case "2":  # Show
                try:
                    print(dataFrame.head())
                except:
                    print("Use the 'select' command to create a DataFrame first.")

            case "3":  # Port scans
                imput = int(input("Select the threshold : "))
                detect_scan_port.scans(dataFrame, imput)

            case "4":  # Detect anomalies
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


            case "5":  # Statistics
                if f.endswith(".pcap") or f.endswith(".log"):
                    dataFrame = parse_data.parse_log(file)
                    
                stats(dataFrame)

            case "6":  # Isolation Forest
                if f.endswith(".pcap") or f.endswith(".log"):
                    dataFrame = parse_data.parse_log(file)
                model = train_isolation_forest(dataFrame, ['length', 'src_port', 'dst_port'])
                anomalies = detect_anomalies(model, dataFrame, ['length', 'src_port', 'dst_port'])
                print(anomalies)
                
            case "7":  # Complete scans
                if f.endswith(".pcap") or f.endswith(".log"):
                    dataFrame = parse_data.parse_log(file)
                
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



 
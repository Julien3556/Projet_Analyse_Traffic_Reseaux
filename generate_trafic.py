import os
import socket
import random
import time
import threading

def generate_tcp_traffic(target_ip, ports, interval=0.05):
    """
    Generates TCP traffic to random ports.

    Arguments:
        - target_ip: str, the target IP address.
        - ports: list, a list of ports to send traffic to.
        - interval: float, the time interval between packets (default: 0.05 seconds).

    Functionality:
        - Randomly selects a port from the provided list.
        - Sends a TCP packet to the selected port.
        - Handles connection errors gracefully.

    Exceptions:
        - ConnectionRefusedError: If the connection to the port is refused.
        - Exception: For any other errors during traffic generation.
    """
    while True:
        try:
            port = random.choice(ports)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, port))
                s.sendall(b"TCP Test Packet")
                print(f"Sent TCP packet to {target_ip}:{port}")
        except ConnectionRefusedError:
            print(f"Connection refused on TCP port {port}")
        except Exception as e:
            print(f"Error in TCP traffic: {e}")
        time.sleep(interval)

def generate_udp_traffic(target_ip, ports, interval=0.05):
    """
    Generates UDP traffic to random ports.

    Arguments:
        - target_ip: str, the target IP address.
        - ports: list, a list of ports to send traffic to.
        - interval: float, the time interval between packets (default: 0.05 seconds).

    Functionality:
        - Randomly selects a port from the provided list.
        - Sends a UDP packet to the selected port.
        - Handles errors gracefully.

    Exceptions:
        - Exception: For any errors during traffic generation.
    """
    while True:
        try:
            port = random.choice(ports)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"UDP Test Packet", (target_ip, port))
                print(f"Sent UDP packet to {target_ip}:{port}")
        except Exception as e:
            print(f"Error in UDP traffic: {e}")
        time.sleep(interval)

def generate_icmp_traffic(target_ip, interval=0.5):
    """
    Generates ICMP traffic (ping).

    Arguments:
        - target_ip: str, the target IP address.
        - interval: float, the time interval between packets (default: 0.5 seconds).

    Functionality:
        - Uses the `ping` command to send ICMP packets.
        - Prints the result of each ping attempt.

    Exceptions:
        - KeyboardInterrupt: Stops the ICMP traffic generation when interrupted.
    """
    try:
        while True:
            # Use the ping command to generate ICMP traffic
            response = os.system(f"ping -c 1 {target_ip} > /dev/null 2>&1")
            if response == 0:
                print(f"Sent ICMP packet to {target_ip}")
            else:
                print(f"Failed to send ICMP packet to {target_ip}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped ICMP traffic generation.")

def generate_random_traffic(target_ip, ports, interval=0.01):
    """
    Generates a mix of TCP and UDP traffic.

    Arguments:
        - target_ip: str, the target IP address.
        - ports: list, a list of ports to send traffic to.
        - interval: float, the time interval between packets (default: 0.01 seconds).

    Functionality:
        - Randomly selects between TCP and UDP traffic generation.
        - Calls the appropriate function to generate the selected traffic type.
    """
    while True:
        protocol = random.choice(["TCP", "UDP"])
        if protocol == "TCP":
            generate_tcp_traffic(target_ip, ports, interval)
        else:
            generate_udp_traffic(target_ip, ports, interval)

if __name__ == "__main__":
    """
    Main function to start traffic generation.

    Functionality:
        - Defines the target IP, port range, and interval.
        - Starts threads for generating TCP, UDP, and ICMP traffic.
        - Waits for the threads to complete (infinite loop).
    """
    target_ip = "192.168.254.131"  # Target IP address
    ports = list(range(1000, 2000))  # Range of ports to use
    interval = 0.01  # Interval between packets (in seconds)

    # Start threads to generate different types of traffic
    tcp_thread = threading.Thread(target=generate_tcp_traffic, args=(target_ip, ports, interval))
    udp_thread = threading.Thread(target=generate_udp_traffic, args=(target_ip, ports, interval))
    icmp_thread = threading.Thread(target=generate_icmp_traffic, args=(target_ip, interval))

    tcp_thread.start()
    udp_thread.start()
    icmp_thread.start()

    # Wait for the threads to finish (they run in infinite loops)
    tcp_thread.join()
    udp_thread.join()
    icmp_thread.join()
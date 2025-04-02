import os
import socket
import random
import time
import threading

def generate_tcp_traffic(target_ip, ports, interval=0.05):
    """Génère du trafic TCP vers des ports aléatoires."""
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
    """Génère du trafic UDP vers des ports aléatoires."""
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
    """Génère du trafic ICMP (ping)."""
    try:
        while True:
            # Utilisation de la commande ping pour générer du trafic ICMP
            response = os.system(f"ping -c 1 {target_ip} > /dev/null 2>&1")
            if response == 0:
                print(f"Sent ICMP packet to {target_ip}")
            else:
                print(f"Failed to send ICMP packet to {target_ip}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped ICMP traffic generation.")

def generate_random_traffic(target_ip, ports, interval=0.01):
    """Génère un mélange de trafic TCP et UDP."""
    while True:
        protocol = random.choice(["TCP", "UDP"])
        if protocol == "TCP":
            generate_tcp_traffic(target_ip, ports, interval)
        else:
            generate_udp_traffic(target_ip, ports, interval)

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Adresse IP cible (localhost)
    ports = list(range(1000, 1100))  # Plage de ports à utiliser
    interval = 0.05  # Intervalle entre les paquets (en secondes)

    # Lancer des threads pour générer différents types de trafic
    tcp_thread = threading.Thread(target=generate_tcp_traffic, args=(target_ip, ports, interval))
    udp_thread = threading.Thread(target=generate_udp_traffic, args=(target_ip, ports, interval))
    icmp_thread = threading.Thread(target=generate_icmp_traffic, args=(target_ip, 0.1))

    tcp_thread.start()
    udp_thread.start()
    icmp_thread.start()

    # Attendre que les threads se terminent (ils tournent en boucle infinie)
    tcp_thread.join()
    udp_thread.join()
    icmp_thread.join()
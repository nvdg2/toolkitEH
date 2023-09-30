from pyric import pyw
import pathlib
import subprocess
import sys
from getpass import getpass

def get_wifi_interfaces():
    wifi_interfaces = pyw.interfaces()
    return wifi_interfaces

def get_device_info(interface):
    nic=pyw.getcard(interface)
    print(f"State: Up") if pyw.isup(nic) else print(f"State: Down")
    print(f"MAC-adres: {pyw.macget(nic)}")
    print(f"Suported modes: {pyw.devmodes(nic)}")
    print(f"Tx power: {pyw.txget(nic)}")
    print("\n")

def change_mac_address(interface, mac_address:str):
    nic=pyw.getcard(interface)

    old_mac=pyw.macget(nic)
    aircrack_dir = pathlib.Path("aircrack-ng/macs")
    aircrack_dir.mkdir(exist_ok=True,parents=True)

    save_location=aircrack_dir/f"{old_mac}.txt"
    with save_location.open("w") as mac_file:
        mac_file.write(f"{old_mac}\n")
    pyw.down(nic)
    pyw.macset(nic,mac_address)
    pyw.up(nic)

    return(f"New MAC-adres: {pyw.macget(nic)}")

# def toggle_mode_of_nic(interface,mode):

    # nic=pyw.getcard(interface)
    # pyw.down(nic)
    # mon=pyw.devadd(nic,f"{interface}mon","monitor")
    # pyw.txset(mon,30,'fixed')
    # pyw.modeset(mon,mode)
    # pyw.up(mon)

    # Probeer het softwarepakket op te roepen met het opdrachtregelcommando "where" (Windows) of "which" (Linux/macOS).
    # if is_software_installed("airmon-ng") == False:
    #     return "airmon-ng is not installed"
    # else:
    #     if mode == "monitor":
    #         subprocess.Popen(["airmon-ng", "start", f"{interface}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #         return "Mode changed to monitor"
    #     elif mode == "managed":
    #         subprocess.Popen(["airmon-ng", "stop", f"{interface}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #         return "Mode changed to managed"


def is_software_installed(software_name):
    try:
        # Probeer het softwarepakket op te roepen met het opdrachtregelcommando "where" (Windows) of "which" (Linux/macOS).
        subprocess.Popen(["where", f"{software_name}"] if 'win' in sys.platform else ["which", f"{software_name}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

if __name__ == "__main__":
    #print(toggle_mode_of_nic("wlo1","monitor"))
    pass
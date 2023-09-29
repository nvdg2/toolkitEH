import psutil
from pyric import pyw
import pathlib

def get_wifi_interfaces():
    wifi_interfaces = pyw.winterfaces()
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
    # pyw.down(nic)
    # pyw.macset(nic,mac_address)
    # pyw.up(nic)

    return(f"New MAC-adres: {pyw.macget(nic)}")


if __name__ == "__main__":

    change_mac_address("wlo1","00:11:22:33:44:55")
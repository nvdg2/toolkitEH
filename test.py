import pyric
from pyric import pyw

# Lijst van beschikbare WiFi-interfaces
wifi_interfaces = pyw.interfaces()

# Print informatie over de WiFi-interfaces
for interface in wifi_interfaces:
    print(f"Interface: {interface.devicename}")
    print(f"MAC-adres: {interface.mac}")
    print(f"Frequentieband: {interface.mode}")
    print(f"Ondersteunde modi: {interface.modes()}")
    print(f"Kanaal: {interface.channel}")
    print(f"Signaalsterkte: {interface.signal}")
    print("\n")

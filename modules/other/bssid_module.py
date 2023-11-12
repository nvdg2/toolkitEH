from scapy.all import sniff, Dot11,RadioTap,Dot11Beacon,Dot11EltCountry
import subprocess
import argparse
import threading
import time
import json
import pathlib
from datetime import datetime
import os

def process_packet(packet):
    try:
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
            flags = packet[Dot11].FCfield
            bssid_info[packet[Dot11].info.decode("utf8")]={
                "Strength": packet[RadioTap].dBm_AntSignal,
                "Mac address":packet[Dot11].addr3,
                "Protected frames": True if bool(flags & 0x40) >> 6 else False,
            }

        if packet.haslayer(Dot11EltCountry):
            bssid_info[packet[Dot11].info.decode("utf8")]["Country"]=packet[Dot11EltCountry].country_string.decode("utf8")

        if packet.haslayer(Dot11Beacon):
            bssid_info[packet[Dot11].info.decode("utf8")]["Encryption"]=f'{packet[Dot11Beacon].network_stats()["crypto"]}'
            bssid_info[packet[Dot11].info.decode("utf8")]["Channel"]=packet[Dot11Beacon].network_stats()["channel"]
    except Exception as e:
        print(f"Something went wrong: {e}")

def start_bssid_scan(interface,shutdown_signal:threading.Event,results:list):
    global bssid_info
    bssid_info={}
    active_channel=1
    while not shutdown_signal.is_set():
        try:
            sniff(iface=f"{interface}mon", prn=process_packet, timeout=0.5)
            print(f"found bssid's: {bssid_info.keys()}")
            active_channel+=1
            if active_channel % 14 == 0:
                active_channel=1
            subprocess.run(f"sudo iwconfig {interface}mon channel {active_channel}", shell=True)

        except Exception as e:
            print(f"Something went wrong: {e}")
    results.append(bssid_info)

def main():
    parser = argparse.ArgumentParser(description="Start bssid scan")
    parser.add_argument("--interface", default="wlo1", help="Name of the network interface to use (default: wlo1)")

    args = parser.parse_args()

    try:
        results=[]
        shutdown_signal=threading.Event()
        subprocess.run(["sudo", "airmon-ng", "start", f"{args.interface}"])
        sniff_thread = threading.Thread(target=start_bssid_scan, args=(args.interface,shutdown_signal,results,))
       
        sniff_thread.start()
        sniff_thread.join()

    except KeyboardInterrupt:

        shutdown_signal.set()
        while len(results)==0:
            time.sleep(1)
        subprocess.run(["sudo", "airmon-ng", "stop", f"{args.interface}mon"])
        
        timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
        bssid_dir = pathlib.Path("bssid_scans")
        bssid_dir.mkdir(exist_ok=True,parents=True)
        save_location=bssid_dir/f"network_scan_{timestamp}.json"
        os.chown(bssid_dir,1000,1000)
        with save_location.open("w") as json_file_raw:
            json.dump(results[0], json_file_raw)

if __name__ == "__main__":
    main()

# flags = packet[Dot11].FCfield
# Extract and print individual flag values
# ds_status = flags & 0x3
# more_fragments = (flags & 0x4) >> 2
# retry = (flags & 0x8) >> 3
# pwr_mgmt = (flags & 0x10) >> 4
# more_data = (flags & 0x20) >> 5
# protected_flag = (flags & 0x40) >> 6
# htc_order_flag = (flags & 0x80) >> 7

# print("DS Status:", ds_status)
# print("More Fragments:", more_fragments)
# print("Retry:", retry)
# print("PWR MGT:", pwr_mgmt)
# print("More Data:", more_data)
# print("Protected Flag:", protected_flag)
# print("+HTC/Order Flag:", htc_order_flag)
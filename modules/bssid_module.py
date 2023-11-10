from scapy.all import sniff, Dot11,RadioTap,Dot11EltRSN,Dot11EltMicrosoftWPA,Dot11Beacon,Dot11EltCountry
import subprocess
import argparse
import time
def process_packet(packet):
    try:
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
            flags = packet[Dot11].FCfield
            bssid_info[packet[Dot11].info.decode("utf8")]={
                "Strength": packet[RadioTap].dBm_AntSignal,
                "Mac address":packet[Dot11].addr3,
                "Protected frames": bool(flags & 0x40) >> 6,
            }
        if packet.haslayer(Dot11EltCountry):
            bssid_info[packet[Dot11].info.decode("utf8")]["Country"]=packet[Dot11EltCountry].country_string.decode("utf8")

        if packet.haslayer(Dot11Beacon):
            bssid_info[packet[Dot11].info.decode("utf8")]["Encryption"]=packet[Dot11Beacon].network_stats()["crypto"]
            bssid_info[packet[Dot11].info.decode("utf8")]["Channel"]=packet[Dot11Beacon].network_stats()["channel"]



    except Exception as e:
        print(f"Something went wrong: {e}")


def start_bssid_scan(interface):
    global bssid_info
    bssid_info={}
    active_channel=1
    subprocess.run(["sudo", "airmon-ng", "start", f"{interface}"])

    while True:
        try:
            sniff(iface=f"{interface}mon", prn=process_packet, timeout=0.5)
            print(bssid_info)
            active_channel+=1
            if active_channel % 14 == 0:
                active_channel=1
            subprocess.run(f"sudo iwconfig {interface}mon channel {active_channel}", shell=True)
        except KeyboardInterrupt:
            subprocess.run(["sudo", "airmon-ng", "stop", f"{interface}mon"])
            exit(0)

def main():
    parser = argparse.ArgumentParser(description="Start bssid scan")
    parser.add_argument("--interface", default="wlo1", help="Name of the network interface to use (default: wlo1)")

    args = parser.parse_args()

    print("Starting bssid scan")
    start_bssid_scan(args.interface)

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
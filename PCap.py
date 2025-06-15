import scapy.all as scapy
import os
import sys
import platform
import ctypes  # ✅ Corrected: Import placed at the top

def check_privileges():
    if os.name != 'nt':
        if os.geteuid() != 0:
            print("❌ Please run the script with root privileges (e.g., sudo).")
            sys.exit(1)
    else:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("❌ Please run this script as Administrator.")
            sys.exit(1)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        print(packet.summary())

def list_interfaces():
    interfaces = scapy.get_if_list()
    print("🧭 Available Interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")
    return interfaces

def sniffer(interface):
    try:
        print(f"\n📡 Sniffing on: {interface}")
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        print(f"⚠️ Sniffing failed: {e}")
        print("💡 Tip: Ensure the interface name is correct and Npcap is installed.")

def main():
    check_privileges()
    interfaces = list_interfaces()

    try:
        choice = int(input("\n🔧 Select an interface by number: ")) - 1
        if 0 <= choice < len(interfaces):
            selected_iface = interfaces[choice]
            sniffer(selected_iface)
        else:
            print("❌ Invalid selection. Exiting.")
    except (ValueError, IndexError):
        print("❌ Invalid input. Please enter a valid number.")
    except KeyboardInterrupt:
        print("\n❎ Sniffer stopped by user.")

if __name__ == "__main__":
    main()

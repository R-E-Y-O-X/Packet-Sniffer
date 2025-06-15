import scapy.all as scapy
import os
import sys
import platform
import ctypes  # For checking admin privileges on Windows

# Function to ensure the script is run with administrative/root privileges
def check_privileges():
    if os.name != 'nt':
        # On Unix/Linux, check for root user
        if os.geteuid() != 0:
            print("Please run the script with root privileges (e.g., sudo).")
            sys.exit(1)
    else:
        # On Windows, check for Administrator
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Please run this script as Administrator.")
            sys.exit(1)

# Function to handle each captured packet
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        print(packet.summary())  # Print summary of IP-layer packets

# Function to list all available network interfaces
def list_interfaces():
    interfaces = scapy.get_if_list()
    print("Available Interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")
    return interfaces

# Function to start sniffing on a selected interface
def sniffer(interface):
    try:
        print(f"\nStarting packet sniffing on: {interface}")
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        print(f"Sniffing failed: {e}")
        print("Tip: Ensure the interface name is correct and that Npcap is installed (Windows only).")

# Main function to coordinate interface selection and sniffing
def main():
    check_privileges()
    interfaces = list_interfaces()

    try:
        # Prompt user to choose interface by number
        choice = int(input("\nSelect an interface by number: ")) - 1
        if 0 <= choice < len(interfaces):
            selected_iface = interfaces[choice]
            sniffer(selected_iface)
        else:
            print("Invalid selection. Exiting.")
    except (ValueError, IndexError):
        print("Invalid input. Please enter a valid number.")
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.")

# Entry point of the script
if __name__ == "__main__":
    main()

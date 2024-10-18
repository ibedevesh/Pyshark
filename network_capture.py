import pyshark
import os
import netifaces

def get_available_interfaces():
    interfaces = []
    for iface in netifaces.interfaces():
        try:
            if netifaces.AF_INET in netifaces.ifaddresses(iface):
                ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
                interfaces.append((iface, ip))
        except:
            pass
    return interfaces

def get_tshark_interfaces(tshark_path):
    import subprocess
    output = subprocess.check_output([tshark_path, "-D"]).decode('utf-8')
    interfaces = []
    for line in output.split('\n'):
        if line:
            index, interface = line.split('. ', 1)
            interfaces.append(interface.strip())
    return interfaces

def live_capture(interface=None):
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    if not os.path.exists(tshark_path):
        raise FileNotFoundError("TShark executable not found. Please install Wireshark or specify the correct path.")

    print(f"Using TShark from: {tshark_path}")

    tshark_interfaces = get_tshark_interfaces(tshark_path)
    print("Available network interfaces:")
    for i, iface in enumerate(tshark_interfaces):
        print(f"{i}: {iface}")
    
    choice = int(input("Enter the number of the interface you want to use: "))
    interface = tshark_interfaces[choice].split(' (')[0]  # Take only the device path

    print(f"Capturing on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, tshark_path=tshark_path)
    for packet in capture.sniff_continuously(packet_count=10):
        print(f'Just arrived: {packet}')

# Reading from a pcap file
def read_pcap(file_path):
    from pyshark import FileCapture
    capture = FileCapture(file_path)
    for packet in capture:
        print(packet)

# Example usage
if __name__ == '__main__':
    print("Starting live capture...")
    live_capture()
    
    # Comment out or remove the pcap reading part if you don't need it
    # print("\nReading from pcap file...")
    # read_pcap('path/to/your/capture.pcap')

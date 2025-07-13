#!/usr/bin/env python3

import subprocess
import xml.etree.ElementTree as ET
import sys
import re
import os
import requests # Required for downloading the OUI file
import time     # For checking the age of the OUI cache file

# --- Configuration ---
OUI_FILE_NAME = "oui.txt" # The name of the OUI database file to be saved locally
OUI_DOWNLOAD_URL = "https://standards-oui.ieee.org/oui/oui.txt" # The direct URL to the OUI text file
OUI_CACHE_LIFETIME_DAYS = 7 # How often to check for a new OUI file (in days)

# --- Helper Functions ---

def load_oui_database(file_path):
    """
    Loads the OUI database from the specified file path.
    Downloads it if not found or if the local copy is too old.
    Returns a dictionary mapping OUI (first 6 hex digits of MAC) to vendor name.
    """
    oui_db = {}
    
    # Check if a local OUI file exists and if it's recent enough
    if os.path.exists(file_path):
        file_mod_time = os.path.getmtime(file_path)
        # Calculate if the file is older than the defined cache lifetime
        if (time.time() - file_mod_time) / (24 * 3600) < OUI_CACHE_LIFETIME_DAYS:
            print(f"  -> Using cached OUI database: '{file_path}'")
        else:
            print(f"  -> Cached OUI database '{file_path}' is older than {OUI_CACHE_LIFETIME_DAYS} days. Attempting to refresh...")
            _download_oui_file(file_path) # Attempt to re-download to refresh the cache
    else:
        print(f"  -> OUI database not found at '{file_path}'. Attempting to download...")
        _download_oui_file(file_path) # Download if the file does not exist locally

    try:
        # After potential download, check if the file now exists before trying to read it
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comment lines (starting with '#')
                    if not line or line.startswith('#'):
                        continue 

                    # Use a regular expression to parse lines like "00-00-00   (hex)		XEROX CORPORATION"
                    match = re.match(r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.*)', line)
                    if match:
                        oui_hex = match.group(1).replace('-', '').upper() # Extract OUI (e.g., "000000") and standardize
                        vendor = match.group(2).strip() # Extract the vendor name
                        oui_db[oui_hex] = vendor # Store in our dictionary
            print(f"  -> Successfully loaded {len(oui_db)} OUI entries from '{file_path}'.")
        else:
            print("  -> OUI database file still not found after download attempt. Vendor lookup will be limited.")

    except Exception as e:
        print(f"Error loading OUI database from '{file_path}': {e}")
    return oui_db

def _download_oui_file(target_path):
    """Downloads the OUI database from IEEE and saves it to target_path."""
    print(f"  -> Downloading OUI database from {OUI_DOWNLOAD_URL}...")
    
    # Define headers to mimic a common web browser. This helps bypass
    # server-side checks that block requests from scripts.
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Referer': 'https://standards-oui.ieee.org/', # Referring page to make the request look more legitimate
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Upgrade-Insecure-Requests': '1',
    }

    try:
        # Make the GET request with the defined headers and a timeout
        response = requests.get(OUI_DOWNLOAD_URL, stream=True, timeout=30, headers=headers)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        # Write the downloaded content to the target file
        with open(target_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"  -> OUI database successfully downloaded to '{target_path}'.")
    except requests.exceptions.RequestException as e:
        print(f"  -> Error downloading OUI database: {e}")
        print("     This might be due to the server blocking automated requests (e.g., checking User-Agent or Referer).")
        print("     Please verify your internet connection or the OUI_DOWNLOAD_URL. As a workaround,")
        print("     you can manually download 'oui.txt' from the URL and place it in the script's directory.")
    except Exception as e:
        print(f"  -> An unexpected error occurred during download: {e}")


def _get_mac_addresses_from_arp_cache_darwin():
    """
    Runs 'sudo arp -an' on macOS to get IP-to-MAC mappings from the ARP cache.
    This is necessary for macOS as Nmap may not get MAC addresses without root.
    Returns a dictionary: {ip_address: mac_address}.
    """
    mac_addresses = {}
    print("  -> Attempting to fetch MAC addresses using 'sudo arp -an'...")
    print("     (You may be prompted for your password for 'sudo').")
    try:
        # Execute 'sudo arp -an'. The user will be prompted for their password by sudo.
        arp_output = subprocess.check_output(['sudo', 'arp', '-an'], text=True, stderr=subprocess.PIPE, timeout=10)
        
        for line in arp_output.splitlines():
            # Example line: "? (192.168.1.1) at 80:69:1A:3E:89:56 on en0 ifscope [ethernet]"
            # Also handles "(incomplete)" entries
            match = re.search(r'\?\s+\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]{17}|\(incomplete\))', line)
            if match:
                ip_address = match.group(1)
                mac_address = match.group(2)
                if mac_address == '(incomplete)':
                    mac_addresses[ip_address] = 'N/A' # Mark as N/A if incomplete
                else:
                    mac_addresses[ip_address] = mac_address.upper() # Store MAC in uppercase
    except subprocess.CalledProcessError as e:
        print(f"  -> Error running 'sudo arp -an': {e.stderr.strip()}")
        print("     Please ensure you have sudo privileges and are able to run 'sudo arp -an' manually.")
        print("     MAC addresses will be listed as 'N/A' for macOS devices due to this error.")
    except FileNotFoundError:
        print("  -> Error: 'arp' command not found. Is it in your system's PATH?")
        print("     MAC addresses will be listed as 'N/A' for macOS devices.")
    except subprocess.TimeoutExpired:
        print("  -> Error: 'sudo arp -an' command timed out. MAC addresses may be incomplete.")
    return mac_addresses

def scan_network(network_range="192.168.1.0/24"):
    """
    Scans the local network for active devices and collects their IP, hostname,
    MAC address, and vendor information. Adapts its logic based on the operating system.
    """
    devices = []
    
    # Determine the script's directory to place the OUI file there
    script_dir = os.path.dirname(os.path.abspath(__file__))
    oui_file_path = os.path.join(script_dir, OUI_FILE_NAME)
    oui_database = load_oui_database(oui_file_path) # Load or initiate download of OUI DB

    # Base Nmap command for host discovery (-sn) and XML output (-oX - for stdout)
    nmap_command_base = ["nmap", "-sn", "-oX", "-"]
    nmap_command_full = nmap_command_base + [network_range]

    arp_cache_macs = {} # This will store IP:MAC mappings, primarily for macOS
    
    print(f"Detected platform: {sys.platform}")

    if sys.platform == 'darwin': # Specific handling for macOS
        print(f"  -> Running on macOS. Nmap will perform basic host discovery (without MACs).")
        print(f"  -> MAC addresses will be fetched from the system's ARP cache via 'sudo arp -an'.")
        arp_cache_macs = _get_mac_addresses_from_arp_cache_darwin()
        if not arp_cache_macs:
            print("  -> Warning: Could not retrieve any MAC addresses from ARP cache. All macOS devices may show 'N/A' for MAC.")
    else: # General handling for Linux/Windows
        print(f"  -> Running on non-macOS platform. Nmap is expected to provide MAC addresses directly (may require sudo).")


    try:
        print(f"Running Nmap scan on {network_range}...")
        # Execute the Nmap command. Nmap is typically run without sudo directly by the script
        # on macOS to avoid 'dnet' errors (MACs are gotten separately). On other OSes,
        # the user might need to run the python script itself with `sudo` if Nmap requires it for MACs.
        nmap_process = subprocess.run(
            nmap_command_full,
            capture_output=True, # Capture stdout and stderr
            text=True,           # Decode stdout/stderr as text
            check=True,          # Raise a CalledProcessError if Nmap returns a non-zero exit code
            timeout=120          # Set a timeout for the Nmap scan (in seconds)
        )
        nmap_xml_output = nmap_process.stdout

        # Parse the XML output from Nmap
        root = ET.fromstring(nmap_xml_output)

        for host_elem in root.findall('host'):
            status = host_elem.find('status')
            if status is not None and status.get('state') == 'up': # Only process 'up' hosts
                ip_address = host_elem.find('address').get('addr')
                
                # Get hostname and sanitize it for display by enclosing in quotes
                hostname_elem = host_elem.find('hostnames/hostname')
                raw_hostname = hostname_elem.get('name') if hostname_elem is not None else "N/A"
                # Enclose hostname in single quotes to handle special characters gracefully in terminal display
                hostname = f"'{raw_hostname}'" 
                
                mac_address = "N/A"
                vendor = "N/A" # Default vendor value

                if sys.platform == 'darwin':
                    # On macOS, retrieve MAC address from the ARP cache data we collected earlier
                    mac_address = arp_cache_macs.get(ip_address, "N/A")
                    if mac_address != 'N/A' and oui_database:
                        # If a MAC address is found, try to look up its vendor using the OUI database
                        oui = mac_address.replace(':', '')[:6].upper() # Extract the OUI part
                        vendor = oui_database.get(oui, "Unknown Vendor (OUI not found)")
                    else:
                        vendor = "N/A (via ARP cache)" # Fallback if no MAC or no OUI DB
                else:
                    # For other platforms, Nmap's XML output usually contains the MAC address and vendor directly
                    for addr_elem in host_elem.findall('address'):
                        if addr_elem.get('addrtype') == 'mac':
                            mac_address = addr_elem.get('addr')
                            # Prioritize Nmap's own vendor information if it provided any
                            vendor = addr_elem.get('vendor')
                            if not vendor and mac_address and oui_database: # Fallback to OUI DB if Nmap didn't provide vendor
                                oui = mac_address.replace(':', '')[:6].upper()
                                vendor = oui_database.get(oui, "Unknown Vendor (OUI not found)")
                            elif not vendor:
                                vendor = "N/A" # If no Nmap vendor and no OUI DB was loaded
                            break # Once MAC is found, no need to check other address tags for this host

                # Add the discovered device information to our list
                devices.append({
                    'ip_address': ip_address,
                    'hostname': hostname,
                    'mac_address': mac_address,
                    'vendor': vendor
                })

    except subprocess.CalledProcessError as e:
        print(f"\nError running Nmap command: {e.args}")
        print(f"  -> Nmap stderr: {e.stderr.strip()}")
        print(f"  -> Nmap stdout: {e.stdout.strip()}") # Sometimes errors are in stdout too
        print("Please ensure Nmap is installed and available in your system's PATH.")
        if sys.platform == 'darwin' and 'dnet: Failed to open device en0' in e.stderr:
            print("  -> Hint: On macOS, the Nmap error 'dnet: Failed to open device en0' confirms Nmap cannot get raw socket access without root.")
            print("     This script is designed to work around that by getting MACs separately via 'arp -an'.")
            print("     The unprivileged Nmap scan for host discovery should typically still work.")
        elif sys.platform != 'darwin':
            print("  -> On non-macOS platforms, Nmap may require elevated privileges (e.g., `sudo`) to get MAC addresses.")
            print("     Try running this Python script with `sudo` if you are on Linux/Windows and facing issues getting MACs.")
    except FileNotFoundError:
        print("\nError: 'nmap' command not found. Please ensure Nmap is installed and in your system's PATH.")
    except ET.ParseError:
        print(f"\nError: Could not parse Nmap XML output. The Nmap command might have failed unexpectedly or returned malformed XML.")
        print(f"  -> Raw Nmap output (if any): {nmap_process.stdout if 'nmap_process' in locals() else 'N/A'}")
    except subprocess.TimeoutExpired:
        print(f"\nError: Nmap scan timed out after 120 seconds. Consider increasing the timeout if your network is large.")


    return devices

# --- Main execution block ---
if __name__ == "__main__":
    # You can specify a different network range here if needed
    scanned_devices = scan_network("192.168.1.0/24")

    if scanned_devices:
        print("\n--- Discovered Devices ---")
        # Print the header row for the table
        # Adjusted column widths to accommodate longer hostnames with quotes and vendor names
        print(f"{'IP Address':<16} {'Hostname':<35} {'MAC Address':<20} {'Vendor':<35}")
        print(f"{'-'*16:<16} {'-'*35:<35} {'-'*20:<20} {'-'*35:<35}")
        # Print the details for each discovered device
        for device in scanned_devices:
            print(f"{device['ip_address']:<16} {device['hostname']:<35} {device['mac_address']:<20} {device['vendor']:<35}")
    else:
        print("\nNo devices found or an error occurred during scan.")

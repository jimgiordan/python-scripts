#!/usr/bin/env python3

import subprocess
import socket
import os
import re
import sys
import logging
import time # For time.sleep for testing, though cron handles real scheduling
import csv # Added for CSV handling
import datetime # Added for date checking

# --- Dependency Check ---
try:
    from tabulate import tabulate
    import requests
except ImportError as e:
    #missing_module = str(e).split("'")[1]
    #print(f"Error: Missing required module '{missing_module}'.")
    #print(f"Please install it by running: pip install {missing_module}")
    #sys.exit(1)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "tabulate", "-q"])
    from tabulate import tabulate
    import requests


# --- Configuration Constants ---
GOOGLE_DNS = "8.8.8.8"
GOOGLE_DNS_PORT = 80
NMAP_SCAN_ARGS = ["-sn"] # -sn performs a ping scan, just host discovery
ARP_CMD = ["arp", "-a"]
KNOWN_HOSTS_FILENAME = "kh.csv" # Changed to CSV
TEMP_HOSTS_DIR = "/tmp"
TABLE_HEADERS = ["Hostname", "IP Address", "MAC Address", "Status", "Vendor"]
RUN_INTERVAL_MINUTES = 5 # How often the script runs in background mode

MAC_OUI_CSV_PATH = os.path.join(TEMP_HOSTS_DIR, "mac-vendors-export.csv") # Path for OUI DB
MAC_OUI_DOWNLOAD_URL = "https://maclookup.app/downloads/csv-database/get-db?t=25-07-18&h=b65016a7457c33dd854b7fd0fb4b9402cd58e85a"
MAX_CSV_AGE_DAYS = 7 # Max age of OUI CSV before re-downloading

# --- File Paths ---
HOME_DIR = os.path.expanduser("~")
KNOWN_HOSTS_FILE_PATH = os.path.join(HOME_DIR, KNOWN_HOSTS_FILENAME)
TEMP_HOSTS_FILE_PATH = os.path.join(TEMP_HOSTS_DIR, KNOWN_HOSTS_FILENAME)
LOG_FILE_PATH = os.path.join(HOME_DIR, "host_scanner.log")

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more verbose output
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=LOG_FILE_PATH,
    filemode='a' # Append to the log file
)

# If running interactively for testing, also print to console
if sys.stdout.isatty(): # Check if running in a TTY (interactive terminal)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(console_handler)

# --- Helper Functions ---

def get_local_ip_range():
    """Determines the local network IP range (e.g., 192.168.1.0/24)."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((GOOGLE_DNS, GOOGLE_DNS_PORT))
        local_ip_parts = s.getsockname()[0].split('.')
        ip_range = ".".join(local_ip_parts[:3]) + ".0/24"
        s.close()
        logging.info(f"Determined local IP range: {ip_range}")
        return ip_range
    except socket.error as e:
        logging.error(f"Error getting local IP: {e}. Check your network connection. Exiting.")
        if s: s.close()
        sys.exit(1)

def run_nmap_scan(ip_range_to_scan):
    """Runs nmap to populate ARP cache."""
    logging.info("Running nmap scan...")
    try:
        subprocess.run(
            ["nmap"] + NMAP_SCAN_ARGS + [ip_range_to_scan],
            capture_output=True,
            check=False # Nmap can exit with non-zero for normal conditions (e.g., no hosts up)
        )
        logging.info("Nmap scan completed.")
    except FileNotFoundError:
        logging.error("Error: 'nmap' command not found. Please install Nmap.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running nmap: {e.stderr.decode()}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during nmap scan: {e}")

def get_arp_table_output():
    """Fetches and returns the raw output of 'arp -a'."""
    logging.info("Running arp command...")
    try:
        result = subprocess.run(
            ARP_CMD,
            capture_output=True,
            text=True, # Decode stdout/stderr as text
            check=True # Raise CalledProcessError if arp command fails
        )
        logging.info("ARP command completed.")
        return result.stdout.splitlines()
    except FileNotFoundError:
        logging.error(f"Error: '{ARP_CMD[0]}' command not found. Make sure it's in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running '{' '.join(ARP_CMD)}': {e.stderr}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred while running ARP: {e}")
        return []

def parse_arp_line(arp_line_str):
    """
    Parses a single ARP line.
    Returns (hostname_or_questionmark, ip_address, mac_address) or None if parsing fails/incomplete.
    """
    match = re.match(r"(\S+)\s+\(((\d{1,3}\.){3}\d{1,3})\)\s+at\s+([0-9a-fA-F:]+|\(incomplete\))", arp_line_str)
    if match:
        hostname_or_q = match.group(1)
        ip_address = match.group(2)
        mac_address = match.group(4)

        if mac_address == "(incomplete)":
            return None # Skip incomplete entries
        else:
            # --- START OF MAC ADDRESS NORMALIZATION ---
            normalized_mac_segments = []
            for segment in mac_address.split(':'):
                try:
                    normalized_mac_segments.append(f"{int(segment, 16):02x}")
                except ValueError:
                    logging.warning(f"Invalid MAC segment '{segment}' in line: {arp_line_str}")
                    return None # Skip this entry if a segment is invalid
            mac_address = ":".join(normalized_mac_segments)
            # --- END OF MAC ADDRESS NORMALIZATION ---
            return hostname_or_q, ip_address, mac_address
    return None

def load_known_hosts(filepath):
    """
    Loads known hosts from a CSV file.
    Returns a tuple: (set of known hosts, boolean indicating if changes were made).
    """
    known_hosts_set = set()
    was_changed = False
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header is None:
                logging.info(f"Known hosts file '{filepath}' is empty.")
                return known_hosts_set, was_changed

            for line_num, row in enumerate(reader, 2):
                if not row or len(row) < 3:
                    if row: logging.warning(f"Skipping malformed row in '{filepath}' at row {line_num}: {row}")
                    continue

                ip_addr, display_name, mac_addr_from_file = row[0].strip(), row[1].strip(), row[2].strip()
                
                normalized_mac_segments = []
                mac_was_normalized = False
                for segment in mac_addr_from_file.split(':'):
                    try:
                        formatted_segment = f"{int(segment, 16):02x}"
                        normalized_mac_segments.append(formatted_segment)
                        if formatted_segment != segment.lower():
                            mac_was_normalized = True
                    except ValueError:
                        logging.warning(f"Invalid MAC segment '{segment}' in known hosts file '{filepath}' at row {line_num}. Skipping entry.")
                        mac_was_normalized = False
                        break
                
                if mac_was_normalized:
                    normalized_mac_addr = ":".join(normalized_mac_segments)
                    known_hosts_set.add((ip_addr, display_name, normalized_mac_addr))
                    was_changed = True
                    logging.info(f"Normalized MAC for {display_name} ({ip_addr}) from '{mac_addr_from_file}' to '{normalized_mac_addr}' during load.")
                else:
                    known_hosts_set.add((ip_addr, display_name, mac_addr_from_file))

    except FileNotFoundError:
        logging.info(f"Known hosts file '{filepath}' not found. Starting with an empty list.")
    except Exception as e:
        logging.error(f"An error occurred while loading known hosts from '{filepath}': {e}")
    
    return known_hosts_set, was_changed

def save_known_hosts(known_hosts_set, filepath):
    """
    Saves the in-memory set of known hosts back to the CSV file.
    Format: IP_ADDRESS,DISPLAY_NAME,MAC_ADDRESS
    """
    try:
        with open(filepath, 'w', encoding='utf-8', newline='') as f: # newline='' is crucial for csv module
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Hostname", "MAC Address"]) # Write header
            for ip_addr, display_name, mac_addr in sorted(list(known_hosts_set)):
                writer.writerow([ip_addr, display_name, mac_addr])
        logging.info(f"Saved {len(known_hosts_set)} known hosts to '{filepath}'.")
    except Exception as e:
        logging.error(f"Error saving known hosts to '{filepath}': {e}")

def download_mac_oui_csv(url, filepath):
    """
    Downloads the MAC OUI CSV file from the given URL and saves it to filepath.
    """
    logging.info(f"Downloading new MAC OUI database from {url}...")
    try:
        response = requests.get(url, stream=True) # Use stream=True for potentially large files
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192): # Iterate over content in chunks
                f.write(chunk)
        logging.info(f"Successfully downloaded MAC OUI database to {filepath}.")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading MAC OUI database: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during download: {e}")
        return False

def load_mac_oui_database(filepath):
    """
    Loads the MAC OUI database from a CSV file into a dictionary.
    Checks file age and downloads new copy if needed.
    Keys are the first 6 hex digits of the MAC (OUI), values are vendor names.
    """
    needs_download = False
    if not os.path.exists(filepath):
        logging.info(f"MAC OUI database not found at {filepath}. Downloading...")
        needs_download = True
    else:
        file_mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
        current_time = datetime.datetime.now()
        file_age = current_time - file_mod_time
        
        if file_age.days >= MAX_CSV_AGE_DAYS:
            logging.info(f"MAC OUI database is {file_age.days} days old. Downloading new copy...")
            needs_download = True
        else:
            logging.info(f"MAC OUI database is {file_age.days} days old. No download needed.")

    if needs_download:
        if not download_mac_oui_csv(MAC_OUI_DOWNLOAD_URL, filepath):
            logging.warning("Failed to download new MAC OUI database. Attempting to use existing (possibly outdated) file.")
            # If download fails, proceed with existing file if it exists, otherwise loading will fail

    mac_oui_db = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    oui = row[0].strip().replace('-', '').replace(':', '').upper()
                    organization = row[1].strip()
                    if oui and organization:
                        mac_oui_db[oui] = organization
        logging.info(f"Loaded {len(mac_oui_db)} MAC OUI entries from {filepath}.")
    except FileNotFoundError:
        logging.error(f"Error: MAC OUI database file not found at {filepath} after download attempt. Cannot proceed.")
    except Exception as e:
        logging.error(f"Error loading MAC OUI database from {filepath}: {e}")
    return mac_oui_db

def get_vendor_from_mac(mac_address, mac_oui_db):
    """
    Looks up the vendor name for a given MAC address using the OUI database.
    """
    if not mac_address or len(mac_address) < 6:
        return "N/A"
    
    # Get the OUI (first 6 hex digits)
    oui = mac_address.replace(':', '').replace('-', '')[:6].upper()
    
    return mac_oui_db.get(oui, "Unknown Vendor")

# --- OS-Specific Notification Functions ---

def _send_macos_notification_and_get_response(title, message, buttons=["No", "Yes"]):
    """Sends an macOS system notification with buttons using osascript."""
    escaped_message = message.replace('"', '\\"')
    button_list = "{" + ", ".join([f'"{b}"' for b in buttons]) + "}"
    script = f'display dialog "{escaped_message}" with title "{title}" buttons {button_list} default button "{buttons[-1]}"'
    
    try:
        process = subprocess.run(
            ['osascript', '-e', script],
            capture_output=True, # Capture output to avoid polluting logs if run in background
            text=True,
            check=False
        )
        if process.returncode == 0:
            output = process.stdout.strip()
            if output.startswith("button returned:"):
                return output.split(":")[1].strip()
        logging.warning(f"macOS notification failed or user closed dialog (exit code {process.returncode}). Output: {process.stderr.strip()}")
        return None # Indicate GUI failed
    except FileNotFoundError:
        logging.warning("Error: 'osascript' command not found. macOS notifications are unavailable.")
        return None
    except Exception as e:
        logging.error(f"An error occurred while sending macOS notification: {e}")
        return None

def _send_linux_notification_and_get_response(title, message, buttons=["No", "Yes"]):
    """Sends an interactive Linux system notification using Zenity."""
    zenity_cmd = ["zenity", "--question", f"--title={title}", f"--text={message}"]
    zenity_cmd += [f"--ok-label={buttons[1]}", f"--cancel-label={buttons[0]}"]

    try:
        # Check if zenity is available without running it fully if not needed
        subprocess.run(["zenity", "--version"], check=True, capture_output=True)
        # We don't capture output for zenity itself, so it can open on display
        result = subprocess.run(zenity_cmd, capture_output=False, check=False)
        if result.returncode == 0:
            return buttons[1] # Yes
        elif result.returncode == 1:
            return buttons[0] # No
        else: # Zenity failed in some other way (e.g., no DISPLAY)
            logging.warning(f"Zenity dialog failed (exit code {result.returncode}). Check DISPLAY environment variable if running via cron.")
            _send_linux_non_interactive_notification(title, message) # Still send a non-interactive alert
            return None # Indicate GUI failed
    except FileNotFoundError:
        logging.warning("Command 'zenity' not found. No interactive notification.")
        _send_linux_non_interactive_notification(title, message)
        return None # Indicate GUI failed
    except Exception as e:
        logging.error(f"Error executing zenity: {e}. No interactive notification.")
        _send_linux_non_interactive_notification(title, message)
        return None # Indicate GUI failed

def _send_linux_non_interactive_notification(title, message):
    """Sends a non-interactive notification using notify-send (for fallback)."""
    try:
        subprocess.run(["notify-send", title, message], check=False)
        logging.info("Sent non-interactive notification via notify-send.")
    except FileNotFoundError:
        logging.warning("Command 'notify-send' not found. Cannot send non-interactive notifications.")
    except Exception as e:
        logging.error(f"Error sending notify-send notification: {e}")

def send_notification_and_get_response(title, message):
    """Dispatches to the appropriate notification function based on OS. Returns 'Yes', 'No', or None (if GUI failed)."""
    logging.info(f"Attempting to send GUI notification for new host: {title} - {message.splitlines()[0]}")
    if sys.platform == 'darwin':
        return _send_macos_notification_and_get_response(title, message)
    elif sys.platform.startswith('linux'):
        return _send_linux_notification_and_get_response(title, message)
    else:
        logging.warning(f"System notifications not supported on {sys.platform}.")
        return None # Indicate GUI failed on unsupported platform

# No more `open_file_in_default_app` as it's not suitable for background.

# --- Main Script Logic ---
def run_scan_cycle():
    logging.info(f"Starting host scan cycle at {time.ctime()}...")
    
    mac_oui_db = load_mac_oui_database(MAC_OUI_CSV_PATH)
    current_known_hosts, known_hosts_changed_on_load = load_known_hosts(KNOWN_HOSTS_FILE_PATH)
    known_hosts_changed_this_scan = False

    local_ip_range = get_local_ip_range()
    run_nmap_scan(local_ip_range)

    arp_lines = get_arp_table_output()
    if not arp_lines:
        logging.warning("No ARP entries found. Scan cycle finished.")
        return

    table_data = []
    new_hosts_count = 0
    for arp_line in arp_lines:
        parsed_entry = parse_arp_line(arp_line)
        if not parsed_entry:
            continue

        hostname_or_q, ip_address, mac_address = parsed_entry
        vendor_name = get_vendor_from_mac(mac_address, mac_oui_db)
        display_name = hostname_or_q if hostname_or_q != '?' else ip_address
        host_tuple = (ip_address, display_name, mac_address)
        
        is_new_host = host_tuple not in current_known_hosts
        status = "New Host" if is_new_host else "Known Host"
        
        table_data.append([display_name, ip_address, mac_address, status, vendor_name])

        if is_new_host:
            new_hosts_count += 1
            logging.info(f"New host detected: {display_name} ({ip_address}) [{mac_address}] - {vendor_name}")
            
            response = send_notification_and_get_response(
                "New Network Host Detected!",
                f"Host: {display_name}\nIP: {ip_address}\nMAC: {mac_address}\nVendor: {vendor_name}\n\nAdd to known hosts?"
            )
            
            if response == "Yes":
                current_known_hosts.add(host_tuple)
                known_hosts_changed_this_scan = True
                table_data[-1][3] = "Known (Added)"
                logging.info(f"Host '{display_name}' added to known hosts.")
            elif response == "No":
                logging.info(f"Host '{display_name}' not added (user choice).")
            else:
                logging.warning(f"Could not get interactive response for '{display_name}'. Host not added.")
    
    table_data.sort(key=lambda row: row[2])

    try:
        with open(TEMP_HOSTS_FILE_PATH, 'w', encoding='utf-8') as kh:
            kh.write(tabulate(table_data, headers=TABLE_HEADERS, tablefmt="plain"))
        logging.info(f"Scan results saved to temporary file: {TEMP_HOSTS_FILE_PATH}")
    except Exception as e:
        logging.error(f"Error writing temporary file: {e}")

    logging.info(f"Scan cycle summary: {len(table_data)} hosts found. {new_hosts_count} new hosts detected.")

    if known_hosts_changed_on_load or known_hosts_changed_this_scan:
        save_known_hosts(current_known_hosts, KNOWN_HOSTS_FILE_PATH)
    else:
        logging.info("No changes to known hosts file needed.")

    logging.info("Host scan cycle finished.")

    

if __name__ == "__main__":
    run_scan_cycle()
    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "requests", "tabulate", "-y", "-q"])

#!/usr/bin/env python3

import subprocess
import socket
import os
import re
from tabulate import tabulate
import sys
import logging
import time # For time.sleep for testing, though cron handles real scheduling

# --- Configuration Constants ---
GOOGLE_DNS = "8.8.8.8"
GOOGLE_DNS_PORT = 80
NMAP_SCAN_ARGS = ["-sn"] # -sn performs a ping scan, just host discovery
ARP_CMD = ["arp", "-a"]
KNOWN_HOSTS_FILENAME = "kh.txt" # Stored in user's home directory
TEMP_HOSTS_DIR = "/tmp"
TABLE_HEADERS = ["Hostname", "IP Address", "MAC Address", "Status"]
RUN_INTERVAL_MINUTES = 5 # How often the script runs in background mode

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
            return hostname_or_q, ip_address, mac_address
    return None

def load_known_hosts(filepath):
    """
    Loads known hosts from a file into a set for efficient lookup.
    Expected format per line: IP_ADDRESS DISPLAY_NAME MAC_ADDRESS
    """
    known_hosts_set = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line:
                    continue
                parts = stripped_line.split(' ')
                if len(parts) >= 3:
                    ip_addr = parts[0]
                    mac_addr = parts[-1]
                    display_name = ' '.join(parts[1:-1])
                    known_hosts_set.add((ip_addr, display_name, mac_addr))
                else:
                    logging.warning(f"Skipping malformed line in '{filepath}' at line {line_num}: '{stripped_line}'")
        logging.info(f"Loaded {len(known_hosts_set)} known hosts from '{filepath}'.")
    except FileNotFoundError:
        logging.info(f"Known hosts file '{filepath}' not found. Starting with an empty known hosts list.")
    except UnicodeDecodeError:
        logging.error(f"Could not decode known hosts file '{filepath}' with UTF-8. Please check encoding.")
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading known hosts from '{filepath}': {e}")
    return known_hosts_set

def save_known_hosts(known_hosts_set, filepath):
    """
    Saves the in-memory set of known hosts back to the file.
    Format per line: IP_ADDRESS DISPLAY_NAME MAC_ADDRESS
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f: # 'w' will overwrite, ensuring correct format
            for ip_addr, display_name, mac_addr in sorted(list(known_hosts_set)):
                f.write(f"{ip_addr} {display_name} {mac_addr}\n")
        logging.info(f"Saved {len(known_hosts_set)} known hosts to '{filepath}'.")
    except Exception as e:
        logging.error(f"Error saving known hosts to '{filepath}': {e}")

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

    # Load known hosts into memory at the start of each cycle
    current_known_hosts = load_known_hosts(KNOWN_HOSTS_FILE_PATH)
    known_hosts_changed = False # Flag to track if we need to rewrite the file

    local_ip_range = get_local_ip_range()
    
    # Always run Nmap in background mode
    run_nmap_scan(local_ip_range)

    arp_lines = get_arp_table_output()
    if not arp_lines:
        logging.warning("No ARP entries found or an error occurred during ARP command.")
        logging.info("Scan cycle finished (no ARP entries).")
        return # Exit this cycle if no ARP data

    table_data = []
    resolved_count = 0
    unresolved_count = 0
    new_hosts_detected_count = 0

    for arp_line in arp_lines:
        parsed_entry = parse_arp_line(arp_line)
        
        if parsed_entry:
            hostname_or_q, ip_address, mac_address = parsed_entry

            if hostname_or_q == '?':
                display_name = ip_address
                unresolved_count += 1
            else:
                display_name = hostname_or_q
                resolved_count += 1

            host_tuple = (ip_address, display_name, mac_address)
            is_new_host = host_tuple not in current_known_hosts

            host_status_text = "New Host" if is_new_host else "Known Host"

            table_data.append([
                display_name,
                ip_address,
                mac_address,
                host_status_text
            ])

            if is_new_host:
                new_hosts_detected_count += 1
                logging.info(f"New host detected: {display_name} ({ip_address}) {mac_address}")
                
                response = send_notification_and_get_response(
                    "New Network Host Detected!",
                    f"Host: {display_name}\nIP: {ip_address}\nMAC: {mac_address}\n\nWould you like to add this host to your known hosts list?"
                )
                
                if response == "Yes":
                    current_known_hosts.add(host_tuple)
                    known_hosts_changed = True
                    table_data[-1][3] = "Known Host (Added)"
                    logging.info(f"Host '{display_name}' added to known hosts.")
                elif response == "No":
                    logging.info(f"Host '{display_name}' not added to known hosts (user chose 'No').")
                else: # response is None (GUI failed)
                    logging.warning(f"Could not get interactive response for host '{display_name}'. Host not automatically added.")
        
    table_data.sort(key=lambda row: socket.inet_aton(row[1]))

    # Write the formatted table to a temporary file for *potential* manual viewing
    try:
        with open(TEMP_HOSTS_FILE_PATH, 'w', encoding='utf-8') as kh:
            kh.write(tabulate(table_data, headers=TABLE_HEADERS, tablefmt="plain"))
        logging.info(f"Scan results saved to temporary file: {TEMP_HOSTS_FILE_PATH}")
    except Exception as e:
        logging.error(f"Error writing temporary file: {e}")

    logging.info(f"Scan cycle summary: {len(table_data)} hosts found ({unresolved_count} unresolved, {resolved_count} resolved). {new_hosts_detected_count} new hosts detected.")

    if known_hosts_changed:
        save_known_hosts(current_known_hosts, KNOWN_HOSTS_FILE_PATH)
    else:
        logging.info("No changes to known hosts file.")

    logging.info("Host scan cycle finished.")

if __name__ == "__main__":
    # The main loop is external for cron/systemd. This script runs one cycle.
    # For local testing, you can uncomment the loop below.
    
    # print(f"Script starting in interactive testing mode. Will run every {RUN_INTERVAL_MINUTES} minutes.")
    # while True:
    #     run_scan_cycle()
    #     logging.info(f"Waiting for {RUN_INTERVAL_MINUTES} minutes...")
    #     time.sleep(RUN_INTERVAL_MINUTES * 60)
    
    # When deployed via cron/launchd, the scheduler calls run_scan_cycle directly
    run_scan_cycle()

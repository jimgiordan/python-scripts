#!/usr/bin/env python3

import subprocess
import os
import sys
import logging
import re
import time # For a simple debounce mechanism

# --- Configuration Constants ---
TRUSTED_SSIDS_FILENAME = "trusted_ssids.txt" # List of trusted Wi-Fi SSIDs, one per line
HOST_SCANNER_SCRIPT_PATH = os.path.join(os.path.expanduser("~"), "dev", "host_scanner", "host_scanner.py")
# Define the EXACT cron job line for host_scanner.py
# This MUST match the line you want to enable/disable in your crontab, excluding any leading '#'
# Ensure the Python path and script path are correct for your system.
HOST_SCANNER_CRON_JOB_LINE = f"*/20 6-22 * * * /Users/jimgiordan/.venv/bin/python3 {HOST_SCANNER_SCRIPT_PATH} >/dev/null 2>&1"

# --- File Paths ---
HOME_DIR = os.path.expanduser("~")
TRUSTED_SSIDS_FILE_PATH = os.path.join(HOME_DIR, TRUSTED_SSIDS_FILENAME)
LOG_FILE_PATH = os.path.join(HOME_DIR, "network_cron_manager.log")
# Debounce file to prevent too frequent runs (e.g., if network status changes rapidly)
DEBOUNCE_FILE_PATH = os.path.join(HOME_DIR, ".network_cron_manager_debounce")
DEBOUNCE_INTERVAL_SECONDS = 60 # Only run the core logic once per minute

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more verbose output
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=LOG_FILE_PATH,
    filemode='a' # Append to the log file
)



# --- Helper Functions ---

def _check_debounce():
    """Checks if enough time has passed since the last run."""
    current_time = time.time()
    if os.path.exists(DEBOUNCE_FILE_PATH):
        try:
            with open(DEBOUNCE_FILE_PATH, 'r') as f:
                last_run_time = float(f.read().strip())
            if (current_time - last_run_time) < DEBOUNCE_INTERVAL_SECONDS:
                logging.info(f"Debouncing: Less than {DEBOUNCE_INTERVAL_SECONDS} seconds since last run. Exiting.")
                return False
        except Exception as e:
            logging.warning(f"Could not read debounce file: {e}. Proceeding.")
    
    try:
        with open(DEBOUNCE_FILE_PATH, 'w') as f:
            f.write(str(current_time))
    except Exception as e:
        logging.warning(f"Could not write to debounce file: {e}. Proceeding.")
        
    return True

def get_current_ssid():
    """
    Gets the current Wi-Fi SSID based on the operating system.
    Returns SSID string or None if not connected or error.
    """
    ssid = None
    
    if sys.platform == 'darwin': # macOS
        command = "ipconfig getsummary $(networksetup -listallhardwareports | awk '/Hardware Port: Wi-Fi/{getline; print $2}') | awk -F ' SSID : ' '/ SSID : / {print $2}'"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            ssid = result.stdout.strip()
            
            if ssid:
                logging.info(f"macOS: SSID found: '{ssid}'")
            else:
                logging.warning("macOS: No SSID found. Is Wi-Fi connected?")

        except subprocess.CalledProcessError as e:
            logging.error(f"macOS: SSID command failed (exit code {e.returncode}): {e.stderr.strip()}")
        except Exception as e:
            logging.error(f"macOS: An unexpected error occurred while getting SSID: {e}")

    elif sys.platform.startswith('linux'): # Linux (Keep your existing Linux logic)
        # ... (your existing Linux detection logic) ...
        pass # Placeholder, copy your Linux logic here
    else:
        logging.warning(f"Unsupported OS for Wi-Fi detection: {sys.platform}")

    if ssid:
        logging.info(f"Final determined Wi-Fi SSID: '{ssid}'")
    else:
        logging.info("Unable to determine current Wi-Fi SSID.")
    return ssid

def load_trusted_ssids(filepath):
    """Loads trusted SSIDs from a file into a set."""
    trusted_ssids = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'): # Ignore empty lines and comments
                    trusted_ssids.add(stripped_line)
        logging.info(f"Loaded {len(trusted_ssids)} trusted SSIDs from '{filepath}'.")
    except FileNotFoundError:
        logging.error(f"Trusted SSIDs file '{filepath}' not found. Please create it with your trusted Wi-Fi names.")
    except UnicodeDecodeError:
        logging.error(f"Could not decode trusted SSIDs file '{filepath}'. Check encoding.")
    except Exception as e:
        logging.error(f"An unexpected error occurred loading trusted SSIDs: {e}")
    return trusted_ssids

def get_current_crontab():
    """Returns the current user's crontab as a list of lines."""
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        # crontab -l returns 1 if no crontab exists, which is fine.
        if "no crontab for" in e.stderr:
            logging.info("No existing crontab found for this user.")
            return []
        logging.error(f"Error listing crontab: {e.stderr.strip()}")
        return []
    except FileNotFoundError:
        logging.error("Error: 'crontab' command not found. Make sure cron is installed and in your PATH.")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred getting crontab: {e}")
        return []

def install_crontab(crontab_lines):
    """Installs the given list of lines as the new crontab."""
    try:
        process = subprocess.run(
            ["crontab", "-"], # '-' tells crontab to read from stdin
            input="\n".join(crontab_lines) + "\n", # Ensure a final newline
            text=True,
            check=True,
            capture_output=True # Capture output to avoid polluting logs
        )
        logging.info("Crontab updated successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing crontab: {e.stderr.strip()}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred installing crontab: {e}")
        return False

def enable_cron_job(job_line):
    """Ensures the specified job line is present and uncommented in crontab."""
    current_crontab = get_current_crontab()
    modified_crontab = []
    job_found_and_enabled = False

    for line in current_crontab:
        stripped_line = line.strip()
        # If the line is the exact job line (uncommented)
        if stripped_line == job_line:
            modified_crontab.append(line) # Keep as is
            job_found_and_enabled = True
        # If the line is the commented version of the job line
        elif stripped_line == f"#{job_line}":
            modified_crontab.append(job_line) # Uncomment it
            job_found_and_enabled = True
            logging.info(f"Enabled cron job: '{job_line}'")
        else:
            modified_crontab.append(line) # Keep other lines

    # If the job was not found at all, add it
    if not job_found_and_enabled:
        modified_crontab.append(job_line)
        logging.info(f"Added and enabled new cron job: '{job_line}'")
    
    # Only update if there are actual changes
    if "\n".join(modified_crontab).strip() != "\n".join(current_crontab).strip():
        return install_crontab(modified_crontab)
    else:
        logging.info(f"Cron job '{job_line}' already enabled/present. No change needed.")
        return True # Already in desired state

def disable_cron_job(job_line):
    """Ensures the specified job line is commented out in crontab."""
    current_crontab = get_current_crontab()
    modified_crontab = []
    job_found_and_disabled = False

    for line in current_crontab:
        stripped_line = line.strip()
        # If the line is the exact job line (uncommented)
        if stripped_line == job_line:
            modified_crontab.append(f"#{job_line}") # Comment it out
            job_found_and_disabled = True
            logging.info(f"Disabled cron job: '{job_line}'")
        # If the line is already the commented version
        elif stripped_line == f"#{job_line}":
            modified_crontab.append(line) # Keep as is
            job_found_and_disabled = True
        else:
            modified_crontab.append(line) # Keep other lines

    # If the job was not found at all, or already commented, no change needed
    if not job_found_and_disabled:
        logging.info(f"Cron job '{job_line}' already disabled/absent. No change needed.")
        return True # Already in desired state

    # Only update if there are actual changes
    if "\n".join(modified_crontab).strip() != "\n".join(current_crontab).strip():
        return install_crontab(modified_crontab)
    else:
        logging.info(f"Cron job '{job_line}' already commented out. No change needed.")
        return True # Already in desired state

# --- Main Logic ---
def main():
    if not _check_debounce():
        return # Exit if debounced

    logging.info("Starting network-based cron manager check.")

    trusted_ssids = load_trusted_ssids(TRUSTED_SSIDS_FILE_PATH)
    if not trusted_ssids:
        logging.error("No trusted SSIDs defined. Cannot manage cron job based on network trust.")
        return

    current_ssid = get_current_ssid()

    if current_ssid and current_ssid in trusted_ssids:
        logging.info(f"Connected to trusted network: '{current_ssid}'. Ensuring host scanner cron job is ENABLED.")
        enable_cron_job(HOST_SCANNER_CRON_JOB_LINE)
    else:
        status_message = f"Not connected to Wi-Fi" if current_ssid is None else f"Connected to untrusted network: '{current_ssid}'"
        logging.info(f"{status_message}. Ensuring host scanner cron job is DISABLED.")
        disable_cron_job(HOST_SCANNER_CRON_JOB_LINE)

    logging.info("Network-based cron manager check finished.")

if __name__ == "__main__":
    main()

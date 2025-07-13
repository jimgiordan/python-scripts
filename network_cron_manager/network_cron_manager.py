#!/usr/bin/env python3

import subprocess
import os
import sys
import logging
import re
import time # For a simple debounce mechanism

# --- Configuration Constants ---
TRUSTED_SSIDS_FILENAME = "trusted_ssids.txt" # List of trusted Wi-Fi SSIDs, one per line
HOST_SCANNER_SCRIPT_PATH = os.path.join(os.path.expanduser("~"), "scripts", "host_scanner.py")
# Define the EXACT cron job line for host_scanner.py
# This MUST match the line you want to enable/disable in your crontab, excluding any leading '#'
# Ensure the Python path and script path are correct for your system.
HOST_SCANNER_CRON_JOB_LINE = f"*/20 6-22 * * * /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 {HOST_SCANNER_SCRIPT_PATH} >/dev/null 2>&1"

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

# If running interactively for testing, also print to console
if sys.stdout.isatty():
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(console_handler)

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

You're right to consider the robustness of pipes, but in this context, they are actually highly efficient and very reliable for connecting standard Unix commands. Pipes are a fundamental and heavily optimized part of how Unix-like operating systems (like macOS) work.

Let's break down that command and discuss its efficiency and any potential "problems":

ipconfig getsummary $(networksetup -listallhardwareports | awk '/Hardware Port: Wi-Fi/{getline; print $2}') | awk -F ' SSID : ' '/ SSID : / {print $2}'

Breakdown and Efficiency:

networksetup -listallhardwareports | awk '/Hardware Port: Wi-Fi/{getline; print $2}'

This part efficiently finds your Wi-Fi interface name (e.g., en0).

networksetup lists all hardware ports.

awk then filters that output: it finds the line "Hardware Port: Wi-Fi", reads the next line (getline), and prints its second field, which is the device name (en0, en1, etc.).

ipconfig getsummary $(...)

The $(...) is command substitution. The output of the first awk command (the interface name, e.g., en0) is then passed as an argument to ipconfig getsummary.

So, this effectively becomes ipconfig getsummary en0 (or en1, etc.). This is exactly the command we confirmed works well for getting your SSID.

| awk -F ' SSID : ' '/ SSID : / {print $2}'

This is the final parsing step.

awk -F ' SSID : ' sets the field separator to the exact string " SSID : ".

/ SSID : / tells awk to only process lines that contain " SSID : ".

{print $2} then prints the second field on that line, which will be your SSID (e.g., "Loire").

Efficiency Assessment:

This one-liner is indeed more efficient than running two separate subprocess.run calls from Python and doing two stages of parsing in Python.

Fewer Process Spawns: Instead of Python spawning networksetup, reading its output, parsing it, then spawning ipconfig, reading its output, and parsing it again, this single shell command allows the shell to manage the pipes and execution, which is highly optimized. It's essentially one subprocess.run(..., shell=True) call in Python.

Native Tool Efficiency: awk is extremely fast and efficient at text processing in the shell.

Potential "Problems" (and why they're usually not an issue here):

Pipes Themselves: Pipes are not a problem. They are robust and performant. The output of one command is directly streamed as input to the next, which is very efficient as it avoids temporary files.

Error Handling in Shell: The main potential "problem" is how errors are handled within the shell pipeline. If networksetup fails, or if awk doesn't find the Wi-Fi interface, or if ipconfig fails, the pipeline might just produce an empty string or an error message to standard error, and the final awk might not find anything to print.

However, when you run this via subprocess.run(..., check=True), Python will raise a CalledProcessError if any command in the pipe exits with a non-zero status, which helps in catching errors.

Whitespace in SSID: As we discussed before, if an SSID itself contained the literal string " SSID : ", this specific awk delimiter could theoretically mess up the parsing. This is extremely unlikely for a real-world SSID.

Conclusion:

The suggested one-liner is a very good and efficient solution for getting the SSID on macOS without sudo. It's concise, leverages native shell tools effectively, and performs well.

I would recommend using this one-liner in your get_current_ssid() function for macOS.

Here's how you'd update your get_current_ssid() function:

Python

import subprocess
import sys
import logging

# (Assuming logging is configured as before)

def get_current_ssid():
    """
    Gets the current Wi-Fi SSID based on the operating system.
    Returns SSID string or None if not connected or error.
    """
    ssid = None
    
    if sys.platform == 'darwin': # macOS
        # Unified shell command to get the SSID
        # 1. Finds Wi-Fi interface using networksetup and awk
        # 2. Gets summary for that interface using ipconfig
        # 3. Parses the SSID from the summary using awk
        command = "ipconfig getsummary $(networksetup -listallhardwareports | awk '/Hardware Port: Wi-Fi/{getline; print $2}') | awk -F ' SSID : ' '/ SSID : / {print $2}'"
        
        try:
            result = subprocess.run(
                command,
                shell=True, # Critical: tells subprocess to execute the string as a shell command
                capture_output=True,
                text=True,
                check=True # Raises CalledProcessError if the command fails
            )
            ssid = result.stdout.strip()
            
            if ssid: # Check if we actually got an SSID (could be empty string if not connected)
                logging.info(f"macOS: SSID found via one-liner: '{ssid}'")
            else:
                logging.warning("macOS: One-liner executed, but no SSID found. Is Wi-Fi connected?")

        except subprocess.CalledProcessError as e:
            logging.error(f"macOS: SSID one-liner command failed (exit code {e.returncode}): {e.stderr.strip()}")
            logging.warning("macOS: This often indicates Wi-Fi is not active or the interface could not be determined.")
        except Exception as e:
            logging.error(f"macOS: An unexpected error occurred while getting SSID with one-liner: {e}")

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

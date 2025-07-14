#!/usr/bin/env python3

import re
import subprocess
import os

# This script reads your SSH configuration file, presents the hosts in a text-based menu,
# and connects to the selected host using the 'ssh' command via subprocess.

def get_ssh_hosts(ssh_config_path='~/.ssh/config'):
    """Parses the SSH config file to extract host names."""
    hosts = []
    # Expand the user directory symbol if present
    expanded_path = os.path.expanduser(ssh_config_path)
    try:
        with open(expanded_path, 'r') as f:
            content = f.read()
            # Find all lines starting with 'Host ' followed by one or more non-whitespace characters
            host_matches = re.findall(r'^Host\s+(\S+)', content, re.MULTILINE)
            # Filter out the wildcard host if it exists
            hosts = [host for host in host_matches if host != '*']
    except FileNotFoundError:
        print(f"Error: SSH config file not found at {expanded_path}")
        print("Please ensure your SSH config file exists and the path is correct.")
    except Exception as e:
        print(f"An error reading SSH config file occurred: {e}")
    return hosts

def select_host_and_ssh():
    """Presents a text-based menu of SSH hosts and connects via SSH."""
    hosts = get_ssh_hosts()

    if not hosts:
        print("No SSH hosts found in your config file.")
        return

    # Use a simple text-based menu
    print("Please select an SSH host by number:")
    for i, host in enumerate(hosts):
        print(f"{i + 1}. {host}")

    while True:
        try:
            choice = input(f"Enter number (1-{len(hosts)}): ")
            index = int(choice) - 1
            if 0 <= index < len(hosts):
                selected_host = hosts[index]
                break
            else:
                print("Invalid number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    print(f"\nSelected host: {selected_host}")
    print(f"Attempting to connect to {selected_host}...")

    # Construct and run the SSH command using subprocess
    try:
        ssh_command = ["ssh", selected_host]
        print(f"Executing command: {' '.join(ssh_command)}")
        # Use subprocess.call for interactive command execution like SSH.
        # This will block until the SSH session is closed.
        subprocess.call(ssh_command)

    except FileNotFoundError:
         print("Error: 'ssh' command not found. Make sure OpenSSH client is installed and in your system's PATH.")
    except subprocess.CalledProcessError as e:
         print(f"SSH command failed with error code {e.returncode}")
         # Depending on your needs, you might want to print stderr here
         # print(f"STDERR:\n{e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred during SSH connection: {e}")


# To run this script:
# Save this code as a Python file (e.g., ssh_menu.py) and run it from your terminal:
# python ssh_menu.py

select_host_and_ssh()

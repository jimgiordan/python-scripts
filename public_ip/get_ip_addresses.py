#!/usr/bin/env python3

import sys
import os

# Add the ~/dev directory to the Python path
# Get the original user's home directory, even when running with sudo -H
# SUDO_USER is set by sudo to the name of the user who invoked sudo
original_user_home = os.path.expanduser(f"~{os.getenv('SUDO_USER')}") if os.getenv('SUDO_USER') else os.path.expanduser('~')
sys.path.insert(0, os.path.join(original_user_home, 'dev'))

from netwk import (
    get_private_ipv4,
    get_public_ip,
    get_gateway_ip,
    get_ipv6_addresses,
    get_mac_address,
    get_open_tcp_ports,
    get_open_udp_ports,
)

def main():
    """Gathers and prints all IP address information."""
    # --- 1. Gather all network information first ---
    private_ipv4 = get_private_ipv4()
    public_ip = get_public_ip()
    mac_address = get_mac_address()
    gateway_ip = get_gateway_ip()  # The router IP is typically the same
    ipv6_addresses = get_ipv6_addresses()
    open_tcp_ports = get_open_tcp_ports()
    open_udp_ports = get_open_udp_ports()

    # --- 2. Organize the primary data for display ---
    data = {
        "Private IPv4": private_ipv4,
        "Public IP": public_ip,
        "MAC Address": mac_address,
        "Gateway / Router": gateway_ip,
    }

    # --- 3. Print all the information ---
    print("Network Information")
    print("-------------------")
    for key, value in data.items():
        print(f"{key+':':<20} {value}")

    # Handle multiple IPv6 addresses
    print(f"{'IPv6 Addresses:':<20} {ipv6_addresses[0]}")
    if len(ipv6_addresses) > 1:
        for addr in ipv6_addresses[1:]:
            print(f"{'':<20} {addr}")

    # Handle multiple open TCP ports
    print(f"\n{'Listening TCP Ports:':<20}", end="")
    # Check the first element of the first tuple for error messages
    if open_tcp_ports and open_tcp_ports[0][0] not in ["None found", "Could not retrieve ports", "Permission denied. Try running with sudo."]:
        # Print the first port on the same line
        first_port, first_service = open_tcp_ports[0]
        print(f" {first_port:<7} {first_service}")
        # Print the rest on subsequent lines
        for port, service in open_tcp_ports[1:]:
            print(f"{' ':<20} {port:<7} {service}")
    else:
        # Print the message from the function on the same line
        print(f" {open_tcp_ports[0][0]}")

    # Handle multiple open UDP ports
    print(f"\n{'Open UDP Ports:':<20}", end="")
    # Check the first element of the first tuple for error messages
    if open_udp_ports and open_udp_ports[0][0] not in ["None found", "Could not retrieve ports", "Permission denied. Try running with sudo."]:
        # Print the first port on the same line
        first_port, first_service = open_udp_ports[0]
        print(f" {first_port:<7} {first_service}")
        # Print the rest on subsequent lines
        for port, service in open_udp_ports[1:]:
            print(f"{'' :<20} {port:<7} {service}")
    else:
        # Print the message from the function on the same line
        print(f" {open_udp_ports[0][0]}")


if __name__ == "__main__":
    main()
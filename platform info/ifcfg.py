import subprocess
import sys

# This script demonstrates how to get network interface details using ifconfig.
# It assumes you have a network service name like "Wi-Fi".

# Example service name, this would come from user input in the full script.
service_name = "Wi-Fi" 
table_data = {}

print(f"Attempting to get details for service: {service_name}")

try:
    # Get the hardware device (e.g., en0) for the given service name
    port_result = subprocess.run(
        ["networksetup", "-gethardwareport", service_name], 
        capture_output=True, text=True, check=True
    )
    device = port_result.stdout.split("Device: ")[1].strip()
    print(f"Found device: {device}")

    # Get all interface details using ifconfig
    ifconfig_result = subprocess.run(
        ["ifconfig", device], 
        capture_output=True, text=True, check=True
    )
    
    print(f"--- Raw ifconfig output for {device} ---")
    print(ifconfig_result.stdout)
    print("------------------------------------")

    for line in ifconfig_result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            table_data['IP address'] = parts[1]
            if len(parts) > 3:
                table_data['Subnet mask'] = parts[3]
            if len(parts) > 5:
                table_data['Broadcast'] = parts[5]
    
    print("\nParsed IPv4 Data:")
    for key, value in table_data.items():
        print(f"- {key}: {value}")

except (subprocess.CalledProcessError, IndexError, FileNotFoundError) as e:
    print(f"\nAn error occurred: {e}")
    print("Could not retrieve ifconfig details. Ensure the service name is correct.")

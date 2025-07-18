"""
networksetup -listallnetworkservices

   * ipconfig is for reading DHCP-assigned network settings.
   * networksetup is for reading the current network configuration, whether it's manual or DHCP.
   * netstat is for reading the live kernel routing table.

networksetup -getinfo "Wi-Fi"
"""

import subprocess
import sys
import asyncio


try:
	from tabulate import tabulate as tb
except ImportError:
	subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "-q"])
	from tabulate import tabulate as tb

def import_clean():
	subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "tabulate", "-y", "-q"])

async def nwkset_data():

	iflist = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output = True, text = True)

	all_services_info = {}
	for service_name in iflist.stdout.splitlines()[1::]:
		info_result = subprocess.run(["networksetup", "-getinfo", service_name], capture_output=True, text=True)
		current_service_data = {}
		for line in info_result.stdout.splitlines():
			if ":" in line:
				parts = line.split(': ', 1)
				if len(parts) == 2 and parts[1]:
					current_service_data[parts[0]] = parts[1]
		all_services_info[service_name] = current_service_data

	for service_name, data in all_services_info.items():
		if "IP address" in data and data["IP address"] != "none":
			table_data = all_services_info[service_name]
			break

	return tb(table_data.items(), headers=["Setting", "Value"], tablefmt = "simple") 

if __name__ == "__main__":
	print( asyncio.run( nwkset_data( ) ) )
	
	import_clean()
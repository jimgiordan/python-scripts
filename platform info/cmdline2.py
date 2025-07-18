"""
networksetup -listallnetworkservices

   * ipconfig is for reading DHCP-assigned network settings.
   * networksetup is for reading the current network configuration, whether it's manual or DHCP.
   * netstat is for reading the live kernel routing table.

networksetup -getinfo "Wi-Fi"
"""

import subprocess
import sys
import os
import platform

original_user_home = os.path.expanduser(f"~{os.getenv('SUDO_USER')}") if os.getenv('SUDO_USER') else os.path.expanduser('~')
sys.path.insert(0, os.path.join(original_user_home, 'dev'))

from netwk import (
#   get_private_ipv4,
#   get_public_ip,
#   get_gateway_ip,
#   get_ipv6_addresses,
#   get_mac_address,
#   get_open_tcp_ports,
#   get_open_udp_ports,
   get_nwkset_data,
   get_ipconfig_data,
)

try:
    from tabulate import tabulate as tb
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "-q"])
    from tabulate import tabulate as tb

if __name__ == "__main__":
   print_data = []
   print_data += get_nwkset_data(sys.platform)
   print_data += get_ipconfig_data(sys.platform)
 
   for line in subprocess.run(["sw_vers"], capture_output=True, text=True).stdout.splitlines():
      print_data.append([line.strip().split(":", 1)[0].strip(), line.strip().split(":", 1)[1].strip()])

   print( tb(print_data, headers=["Setting","Value"] , tablefmt="rounded_outline") )
   
subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "tabulate", "-y", "-q"])

for x in dir(platform):
   if not x.startswith("_"):
      try:
         attribute = getattr(platform, x)
         if callable(attribute):
            # If it's a function, call it and print its result
            print(f"{x}(): {attribute()}")
         else:
            # If it's a regular attribute, print its value
            print(f"{x}: {attribute}")
      except Exception as e:
         # Some attributes might raise errors if accessed directly or without arguments
         print(f"{x}: Could not retrieve ({e})")

for x in platform.uname():
   print(x)

x = platform.python_build()

print(x)
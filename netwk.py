#!/usr/bin/env python3
import socket
import subprocess
import sys

dbg = False

try:
    import netifaces
except ImportError:
    if dbg:
        print("Info: 'netifaces' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "netifaces", "-q"])
    import netifaces

try:
    import requests
except ImportError:
    if dbg:
        print("Info: 'requests' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

try:
    import psutil
except ImportError:
    if dbg:
        print("Info: 'psutil' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

def get_private_ipv4():
    """Gets the primary private IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0)
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return "Not available"

def get_ipv6_addresses():
    """Gets all non-link-local IPv6 addresses."""
    ipv6_addrs = []
    try:
        for iface in netifaces.interfaces():
            ifaddrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET6 in ifaddrs:
                for addr_info in ifaddrs[netifaces.AF_INET6]:
                    addr = addr_info.get('addr')
                    if addr and not addr.startswith('fe80::'):
                        # Remove scope ID if present
                        ipv6_addrs.append(addr.split('%')[0])
        return ipv6_addrs if ipv6_addrs else ["Not available"]
    except Exception:
        return ["Not available"]

def get_gateway_ip():
    """Gets the default gateway IP address."""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except Exception:
        return "Not available"

def get_public_ip():
    """Gets the public IP address from an external service."""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return "Not available"

def get_mac_address():
    """Gets the MAC address of the primary network interface."""
    try:
        # Find the interface associated with the default gateway
        gws = netifaces.gateways()
        default_gateway = gws['default'][netifaces.AF_INET]
        interface = default_gateway[1]

        # Get the MAC address for that interface
        ifaddrs = netifaces.ifaddresses(interface)
        return ifaddrs[netifaces.AF_LINK][0]['addr']
    except (KeyError, IndexError, TypeError):
        # Fallback if gateway method fails
        try:
            for iface_name in netifaces.interfaces():
                ifaddrs = netifaces.ifaddresses(iface_name)
                if netifaces.AF_LINK in ifaddrs and ifaddrs[netifaces.AF_LINK]:
                    mac = ifaddrs[netifaces.AF_LINK][0].get('addr')
                    # Avoid loopback and obviously virtual interfaces
                    if mac and not iface_name.startswith('lo'):
                        return mac
            return "Not available"
        except Exception:
            return "Not available"


def get_open_tcp_ports():
    """
    Gets a list of unique open TCP ports and their service names.
    Returns a list of (port, service_name) tuples or a list with a single error string.
    """
    open_ports_map = {}
    try:
        connections = psutil.net_connections(kind='tcp')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                port = conn.laddr.port
                # Only do the lookup if we haven't seen this port before
                if port not in open_ports_map:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = "Unknown"
                    open_ports_map[port] = service

        if not open_ports_map:
            return [("None found", "")]

        # Sort by port number (the key of the dict)
        sorted_ports = sorted(open_ports_map.items())
        return sorted_ports

    except psutil.AccessDenied:
        return [("Permission denied. Try running with sudo.", "")]
    except psutil.Error:
        return [("Could not retrieve ports", "")]


def get_open_udp_ports():
    """
    Gets a list of unique open UDP ports and their service names.
    Returns a list of (port, service_name) tuples or a list with a single error string.
    """
    open_ports_map = {}
    try:
        # For UDP, there is no "LISTEN" status, we just look for bound sockets
        connections = psutil.net_connections(kind='udp')
        for conn in connections:
            if conn.laddr and conn.laddr.port:
                port = conn.laddr.port
                if port not in open_ports_map:
                    try:
                        service = socket.getservbyport(port, 'udp')
                    except OSError:
                        service = "Unknown"
                    open_ports_map[port] = service

        if not open_ports_map:
            return [("None found", "")]

        # Sort by port number (the key of the dict)
        sorted_ports = sorted(open_ports_map.items())
        return sorted_ports

    except psutil.AccessDenied:
        return [("Permission denied. Try running with sudo.", "")]
    except psutil.Error:
        return [("Could not retrieve ports", "")]

def get_nwkset_data(platform):
    if platform != "darwin":
        return [("Error", "Not a macOS machine")]

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

    return table_data.items()

def get_ipconfig_data(platform):
    if platform != "darwin":
        return [("Error", "Not a macOS machine")]

    iflist = subprocess.run(["ipconfig", "getiflist"], capture_output=True, text = True)
    for ifc in iflist.stdout.split():
        if subprocess.run(["ipconfig", "getifaddr", ifc], capture_output=True, text=True).stdout:
            summary = subprocess.run(["ipconfig", "getsummary", ifc], capture_output=True, text=True)
        else:
            pass

    table_data={}
    for line in summary.stdout.splitlines():
        line = line.strip()
        split_arg = [" = ", " : ", ": "]
        for x in split_arg:
            if x in line:
                table_data[line.split(x, 1)[0]] = line.split(x, 1)[1]
                break
            else:
                pass

    return_data={}
    data_keys = [
    {"yiaddr" : "IP address"},
    {"subnet_mask (ip)" : "Subnet mask"}, 
    {"Router" : "Router"}, 
    {"chaddr" : "MAC sddress"},
    {"SSID" : "Wi-Fi Node"}
    ]
    for map_key in data_keys:
        return_data[map_key[ list(map_key.keys())[0] ]] = table_data.get(list(map_key.keys())[0])

    return return_data.items()

subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "netifaces", "requests", "psutil", "-y", "-q"])
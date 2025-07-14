#!/usr/bin/env python3

# Import standard library modules
import os
import sys
import platform as pf
import subprocess
import re
import asyncio # For asynchronous operations
from typing import List, Dict, Any, Tuple, Optional

# Global variable for current platform for cleaner access
CURRENT_PLATFORM = sys.platform

# Import installed modules or attempt to install them
try:
    import netifaces as ni
    import tabulate as tb
except ImportError:
    print("netifaces or tabulate not found. Attempting to install...")
    try:
        if "linux" in CURRENT_PLATFORM:
            # For Linux, prefer apt for system-wide installs if running with sudo
            # Note: For production, a virtual environment is often better than system-wide installs.
            print("Running apt update and installing dependencies...")
            subprocess.run(["sudo", "apt", "update", "-y"], check=True, capture_output=True)
            subprocess.run(["sudo", "apt", "install", "python3-netifaces", "python3-tabulate", "-y"], check=True, capture_output=True)
        else:
            # For other platforms, use pip3
            print("Running pip install dependencies...")
            subprocess.run([sys.executable, "-m", "pip", "install", "netifaces", "tabulate"], check=True, capture_output=True, text=True)
        import netifaces as ni
        import tabulate as tb
        print("netifaces and tabulate installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies. Command '{e.cmd}' failed with return code {e.returncode}")
        # Ensure stdout/stderr are decoded for error reporting
        stdout_content = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else str(e.stdout)
        stderr_content = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
        print(f"STDOUT: {stdout_content}")
        print(f"STDERR: {stderr_content}")
        sys.exit(1) # Exit if essential dependencies cannot be installed
    except Exception as e:
        print(f"An unexpected error occurred during dependency installation: {e}")
        sys.exit(1) # Exit if essential dependencies cannot be installed


## Initialisation bits
# Debug flag: Set to True for verbose output during execution
# dbg = False # Removed dbg variable
# csc = False # Original variable, commented out as not used

# Define path for the report file based on the operating system
if "win32" in CURRENT_PLATFORM:
    report_output_dir = "" # Current directory on Windows
else:
    report_output_dir = "/tmp/" # Standard temporary directory on Linux/macOS
report_file_name = "pfinf.txt"
full_report_filepath = os.path.join(report_output_dir, report_file_name)

# Define headers for tabular output using 'tabulate'
NI_LST_HDR = ["--- netifaces --- ", ""]
PYT_LST_HDR = ["---python info --- ", ""]
MCH_LST_HDR = ["---machine info--- ", ""]
SYS_LST_HDR = ["   ---  sys  ---   ", ""]
OS_LST_HDR = ["    ---  os  ---    ", ""]
CLI_LST_HDR = ["---CLI commands ---", ""]
LNX_LST_HDR = ["---linux details---", ""]
ARP_HDR = ["Name", "IP4", "MAC", "Interface"] # Corrected "name" to "Name" for consistency
SN_HDR = ["Hostname", "IP Address", "Port", "Service"]
STD_HDR = ["Key", "Value"]
TBLFMT = "rounded_outline" # Table format for tabulate

# Dictionary mapping platforms to available report types
AVAILABLE_REPORTS: Dict[str, List[str]] = {
    "darwin": ["command line", "python", "machine", "arp", "netifaces", "system", "os", "nmap"],
    "linux": ["command line", "python", "machine", "arp", "netifaces", "system", "os", "linux", "nmap"],
    "win32": ["command line", "python", "machine", "system", "os", "windows"]
}
## Initialisation done

# --- Helper function for running shell commands ---
def run_command(cmd: List[str], shell: bool = False, check: bool = True,
                capture_output: bool = True) -> bytes: # <-- Returns bytes
    """
    Executes a shell command using subprocess.run().
    Args:
        cmd: A list of command arguments (preferred for security) or a single string (if shell=True).
        shell: If True, the command is executed through the shell. Use with caution due to security risks.
        check: If True, raises subprocess.CalledProcessError on non-zero exit code.
        capture_output: If True, captures stdout and stderr.

    Returns:
        The standard output (stdout) of the command as raw bytes.

    Raises:
        subprocess.CalledProcessError: If check=True and the command returns a non-zero exit status.
        FileNotFoundError: If the command executable is not found.
        Exception: For other unexpected errors during subprocess execution.
    """
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            capture_output=capture_output,
            text=False, # Explicitly ensure output is bytes from subprocess.run
        )
        return result.stdout # Return raw bytes
    except subprocess.CalledProcessError as e:
        # Ensure e.stdout and e.stderr are decoded for consistent printing
        stdout_content = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else str(e.stdout)
        stderr_content = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
        
        command_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        print(f"Error executing command: '{command_str}'")
        print(f"Return Code: {e.returncode}")
        print(f"Stdout (partial): {stdout_content[:200]}..." if stdout_content else "None") # Show first 200 chars
        print(f"Stderr: {stderr_content}")
        raise # Re-raise the exception to propagate it up the call stack
    except FileNotFoundError:
        command_name = cmd[0] if isinstance(cmd, list) else cmd.split()[0]
        print(f"Command not found: '{command_name}'. Please ensure it is installed and in your system's PATH.")
        raise # Re-raise to propagate
    except Exception as e:
        command_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        print(f"An unexpected error occurred while running command '{command_str}': {e}")
        raise

# --- Asynchronous Nmap Scan Function ---
async def async_scan_network() -> str:
    """
    Performs an Nmap scan asynchronously to avoid blocking the main event loop.
    Parses the Nmap greppable output and formats it into a table.
    """
    try:
        # Determine the default gateway and construct the subnet for Nmap scan
        default_gw_info = ni.gateways().get("default", {}).get(ni.AF_INET)
        if not default_gw_info:
            return "Error: Could not determine default gateway for IPv4 to perform Nmap scan."

        gateway_ip = default_gw_info[0]
        # Assume a /24 subnet for the local network (common for home networks)
        # Adjust if your network uses a different subnet mask
        subnet = f"{'.'.join(gateway_ip.split('.')[:-1])}.0/24"

        print(f"Starting Nmap scan on {subnet} (this may take a while and requires 'nmap' to be installed)...")

        # Use asyncio.create_subprocess_exec for safer execution (no shell interpretation)
        # -T5: Aggressive timing (faster, but more likely to be detected/blocked)
        # -oG -: Output in greppable format to stdout
        process = await asyncio.create_subprocess_exec(
            "nmap", "-T5", "-oG", "-", subnet,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Wait for the Nmap process to complete and capture its output
        stdout_bytes, stderr_bytes = await process.communicate()
        stdout_str = stdout_bytes.decode("utf-8", errors="ignore").strip() # Decode for processing/display
        stderr_str = stderr_bytes.decode("utf-8", errors="ignore").strip()

        if process.returncode != 0:
            # Nmap can return non-zero for various reasons (e.g., no hosts found, permission issues)
            return (f"Nmap scan command failed with exit code {process.returncode}.\n"
                    f"Stderr: {stderr_str}\n"
                    "Ensure nmap is installed, you have necessary network permissions, and the subnet is correct.")

        sn_lst: List[List[str]] = []
        # Parse each line of the Nmap greppable output
        for line in stdout_str.splitlines():
            # Regex to extract Host IP, Hostname, and Ports string
            # Handles cases where hostname might be empty ()
            match = re.search(r'Host: ([\d.]+) \((.*?)\)\s+Ports: (.*)', line)
            if match:
                ip_address = match.group(1).strip()
                hostname = match.group(2).strip() or "N/A" # Use N/A if hostname is empty
                ports_str = match.group(3).strip()

                # Regex to find open TCP ports and their services
                # Captures port number and service name. (?:...) is a non-capturing group for // or /
                ports = re.findall(r'(\d+)/open/tcp//([^/]*?)(?://|/)', ports_str)

                if ports: # Only add hosts that have at least one open TCP port
                    for port, service in ports:
                        sn_lst.append([hostname, ip_address, port, service or "N/A"]) # Service can be empty

        if not sn_lst:
            return "Nmap scan completed, but no open TCP ports found on hosts."

        return tb.tabulate(sn_lst, headers=SN_HDR, tablefmt=TBLFMT)
    except FileNotFoundError:
        return "Error: 'nmap' command not found. Please install Nmap (e.g., 'sudo apt install nmap' on Linux)."
    except Exception as e:
        return f"An unexpected error occurred during Nmap scan: {e}"

# --- Information Gathering Functions (using run_command) ---

def get_cli_info() -> str:
    """
    Gathers various system and network information using command-line tools
    specific to the operating system.
    """
    cli_lst: List[List[str]] = []

    if "darwin" in CURRENT_PLATFORM:
        # run_command returns bytes, so decode for printing/list append
        cli_lst.append(["ssid",
                       run_command(
                           "ipconfig getsummary $(networksetup -listallhardwareports | awk '/Hardware Port: Wi-Fi/{getline; print $2}') | awk -F ' SSID : ' '/ SSID : / {print $2}'",
                            shell=True, # Critical: tells subprocess to execute the string as a shell command
                            capture_output=True,
                            check=True # Raises CalledProcessError if the command fails
                        ).decode("utf-8", errors="replace").strip()])
        cli_lst.append(["gateway", run_command(["ipconfig", "getoption", "en0", "router"]).decode("utf-8", errors="replace").strip()])
        cli_lst.append(["ip4", run_command(["ipconfig", "getifaddr", "en0"]).decode("utf-8", errors="replace").strip()])
        
        # CLEANED UP: scutil --nwi | grep address | awk '{print $3}'
        try:
            # print("DEBUG: Getting scutil --nwi output...") # Removed debug print
            scutil_output_str = run_command(["scutil", "--nwi"], shell=False, check=True).decode("utf-8", errors="replace").strip() # Decode to str
            # print(f"DEBUG: scutil_output_str type: {type(scutil_output_str)}") # Removed debug print
            
            # Process output in Python instead of grep/awk
            alt_ip4 = "N/A"
            for line in scutil_output_str.splitlines():
                if "address" in line:
                    match = re.search(r'address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if match:
                        alt_ip4 = match.group(1)
                        break
            cli_lst.append(["alt_cmd ip4", alt_ip4])
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            cli_lst.append(["alt_cmd ip4", f"Error running command: {e}"])
        except Exception as e:
            error_detail = ""
            if isinstance(e, subprocess.CalledProcessError):
                output = e.output.decode('utf-8', errors='replace') if isinstance(e.output, bytes) else str(e.output)
                stderr = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else str(e.stderr)
                error_detail = f"Command failed with code {e.returncode}. Output: {output}, Stderr: {stderr}"
            else:
                try: error_detail = str(e)
                except Exception as inner_e: error_detail = f"Failed to stringify exception: {type(e).__name__} object. Inner error: {inner_e}"
            cli_lst.append(["alt_cmd ip4", f"An unexpected error occurred: {error_detail}"])


        # CLEANED UP: ifconfig en0 | grep inet6 | grep -v temp | awk '{print $2}'
        try:
            # print("DEBUG: Getting ifconfig en0 output...") # Removed debug print
            ifconfig_output_str = run_command(["ifconfig", "en0"], shell=False, check=True).decode("utf-8", errors="replace").strip() # Decode to str
            # print(f"DEBUG: ifconfig_output_str type: {type(ifconfig_output_str)}") # Removed debug print
            
            # Process output in Python instead of grep/awk
            ipv6_addr = "N/A"
            for line in ifconfig_output_str.splitlines():
                if "inet6" in line and "temp" not in line:
                    match = re.search(r'inet6\s+([0-9a-fA-F:]+)', line)
                    if match:
                        ipv6_addr = match.group(1)
                        break
            cli_lst.append(["ip6", ipv6_addr])
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            cli_lst.append(["ip6", f"Error running command: {e}"])
        except Exception as e:
            error_detail = ""
            if isinstance(e, subprocess.CalledProcessError):
                output = e.output.decode('utf-8', errors='replace') if isinstance(e.output, bytes) else str(e.output)
                stderr = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else str(e.stderr)
                error_detail = f"Command failed with code {e.returncode}. Output: {output}, Stderr: {stderr}"
            else:
                try: error_detail = str(e)
                except Exception as inner_e: error_detail = f"Failed to stringify exception: {type(e).__name__} object. Inner error: {inner_e}"
            cli_lst.append(["ip6", f"An unexpected error occurred: {error_detail}"])


        cli_lst.append(["sw_vers PN", run_command(["sw_vers", "-productName"]).decode("utf-8", errors="replace").strip()])
        cli_lst.append(["sw_vers PV", run_command(["sw_vers", "-productVersion"]).decode("utf-8", errors="replace").strip()])
        cli_lst.append(["hostname", run_command(["hostname"]).decode("utf-8", errors="replace").strip()])

        for opt in ["m", "n", "o", "p", "r", "s", "v"]:
            cli_lst.append([f"uname -{opt}", run_command(["uname", f"-{opt}"]).decode("utf-8", errors="replace").strip()]) # Label improved

    elif "linux" in CURRENT_PLATFORM:
        default_interface_str: str = "eth0" # Default fallback
        try:
            # print("DEBUG: Getting ip route output...") # Removed debug print
            ip_route_output_str = run_command(["ip", "route"], shell=False, check=True).decode("utf-8", errors="replace").strip() # Decode to str
            # print(f"DEBUG: ip_route_output_str type: {type(ip_route_output_str)}") # Removed debug print
            
            # Process output in Python instead of awk
            default_interface_match = re.search(r'default via \S+ dev (\S+)', ip_route_output_str)
            if default_interface_match:
                default_interface_str = default_interface_match.group(1)
            
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not determine default interface using 'ip route'. Falling back to {default_interface_str}.")
            # if dbg: print(f"Error: {e.stderr}") # Removed debug print
        except FileNotFoundError as e:
             print(f"Warning: 'ip' command not found. Cannot determine default interface. Falling back to {default_interface_str}.")
             # if dbg: print(f"Error: {e}") # Removed debug print

        # Get gateway for the default interface
        try:
            gateway_output_str = run_command(["ip", "route", "show", "dev", default_interface_str], shell=False, check=True).decode("utf-8", errors="replace").strip() # Decode to str
            gateway_match = re.search(r'default via ([\d.]+)', gateway_output_str)
            cli_lst.append(["gateway", gateway_match.group(1) if gateway_match else "N/A"])
        except subprocess.CalledProcessError:
            cli_lst.append(["gateway", "N/A"])
        except FileNotFoundError:
            cli_lst.append(["gateway", "N/A (ip command not found)"])


        # Get IPv4 address for the default interface
        try:
            ipv4_output_str = run_command(["ip", "addr", "show", default_interface_str], shell=False, check=True).decode("utf-8", errors="replace").strip() # Decode to str
            ipv4_match = re.search(r'inet ([\d.]+)/\d+', ipv4_output_str)
            cli_lst.append(["ip4", ipv4_match.group(1) if ipv4_match else "N/A"])
        except subprocess.CalledProcessError:
            cli_lst.append(["ip4", "N/A"])
        except FileNotFoundError:
            cli_lst.append(["ip4", "N/A (ip command not found)"])


        # Get global unicast IPv6 address for the default interface
        try:
            ipv6_output_str = run_command(["ip", "addr", "show", default_interface_str], shell=False, check=True).decode("utf-8", errors="replace").strip() # Decode to str
            ipv6_match = re.search(r'inet6 ([\da-f:]+)/\d+\s+scope global', ipv6_output_str)
            if ipv6_match:
                cli_lst.append(["ip6", ipv6_match.group(1)])
            else:
                cli_lst.append(["ip6", "N/A (No global IPv6)"])
        except subprocess.CalledProcessError:
            cli_lst.append(["ip6", "N/A (Error getting IPv6)"])
        except FileNotFoundError:
            cli_lst.append(["ip6", "N/A (ip command not found)"])


        # Get uname information
        for opt in ["m", "n", "o", "p", "r", "s", "v"]:
            cli_lst.append([f"uname -{opt}", run_command(["uname", f"-{opt}"]).decode("utf-8", errors="replace").strip()])

    elif "win32" in CURRENT_PLATFORM:
        # For Windows, parsing ipconfig output can be complex; using shell=True with findstr is practical
        try:
            ipconfig_output_bytes = run_command("ipconfig /all", shell=True, check=True) # /all for more details
            ipconfig_output_str = ipconfig_output_bytes.decode("utf-8", errors="replace").strip()

            gateway_match = re.search(r"Default Gateway[ .]*: ([\d.]+)", ipconfig_output_str)
            ipv4_match = re.search(r"IPv4 Address[ .]*: ([\d.]+)", ipconfig_output_str)
            
            cli_lst.append(["gateway", gateway_match.group(1) if gateway_match else "N/A"])
            cli_lst.append(["ip4", ipv4_match.group(1) if ipv4_match else "N/A"])
            
            # Systeminfo output can be very long, capture specific lines
            systeminfo_summary_bytes = run_command(
                "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Manufacturer\" /C:\"System Model\" /C:\"Total Physical Memory\"",
                shell=True, check=False # Don't check as findstr might not always return 0
            )
            systeminfo_summary_str = systeminfo_summary_bytes.decode("utf-8", errors="replace").strip()
            cli_lst.append(["systeminfo summary", systeminfo_summary_str.strip() or "N/A"]) # Handle empty output
        except Exception as e:
            cli_lst.append(["Error getting network/systeminfo", f"Error: {e}"])

    else:
        cli_lst.append(["Error", "Unsupported platform for CLI info"])
    return tb.tabulate(cli_lst, headers=CLI_LST_HDR, tablefmt=TBLFMT)

def get_ni_info() -> str:
    """
    Gathers network interface information using the 'netifaces' module.
    """
    ni_lst: List[List[str]] = []
    try:
        # Get default gateway information for IPv4
        default_gw_info = ni.gateways().get("default", {}).get(ni.AF_INET)
        if not default_gw_info:
            return tb.tabulate([["Error", "No default IPv4 gateway found"]], headers=NI_LST_HDR, tablefmt=TBLFMT)

        gateway_address = default_gw_info[0]
        interface = default_gw_info[1]
        ni_lst.append(["Default Gateway", gateway_address])
        ni_lst.append(["Default Interface", interface])

        # Get IPv4 address of the default interface
        ipv4_info = ni.ifaddresses(interface).get(ni.AF_INET)
        if ipv4_info and ipv4_info[0].get("addr"):
            ni_lst.append(["IPv4 Address", ipv4_info[0]["addr"]])
            ni_lst.append(["IPv4 Netmask", ipv4_info[0].get("netmask", "N/A")])
            ni_lst.append(["IPv4 Broadcast", ipv4_info[0].get("broadcast", "N/A")])
        else:
            ni_lst.append(["IPv4 Address", "N/A"])

        # Get global IPv6 address of the default interface (excluding link-local)
        ipv6_info = ni.ifaddresses(interface).get(ni.AF_INET6)
        if ipv6_info:
            global_ipv6_addrs = [item["addr"] for item in ipv6_info if item.get("addr") and not item["addr"].startswith("fe80:")]
            if global_ipv6_addrs:
                ni_lst.append(["IPv6 Address (Global)", global_ipv6_addrs[0]]) # Just take the first global one
            else:
                ni_lst.append(["IPv6 Address (Global)", "N/A"])
        else:
            ni_lst.append(["IPv6 Address (Global)", "N/A"])

        # Get MAC address of the default interface
        mac_info = ni.ifaddresses(interface).get(ni.AF_LINK)
        if mac_info and mac_info[0].get("addr"):
            ni_lst.append(["MAC Address", mac_info[0]["addr"]])
        else:
            ni_lst.append(["MAC Address", "N/A"])

    except ValueError as e:
        # Handle cases where interface might not have AF_INET, AF_INET6, or AF_LINK addresses
        ni_lst.append(["Error", f"Could not retrieve full netifaces info for default interface: {e}"])
    except Exception as e:
        ni_lst.append(["Error", f"An unexpected error occurred getting netifaces info: {e}"])

    return tb.tabulate(ni_lst, headers=NI_LST_HDR, tablefmt=TBLFMT)

def get_pyt_info() -> str:
    """
    Gathers various Python interpreter-specific information.
    """
    pyt_lst: List[List[str]] = []
    pyt_lst.append(["Branch", pf.python_branch()])
    # pf.python_build() returns a tuple (build_number, build_date), convert to string
    pyt_lst.append(["Build", str(pf.python_build())])
    pyt_lst.append(["Compiler", pf.python_compiler()])
    pyt_lst.append(["Implementation", pf.python_implementation()])
    pyt_lst.append(["Revision", pf.python_revision()])
    pyt_lst.append(["Python Version", pf.python_version()])
    return tb.tabulate(pyt_lst, headers=PYT_LST_HDR, tablefmt=TBLFMT)

def get_mch_info() -> str:
    """
    Gathers various machine-specific hardware and OS information.
    """
    mch_lst: List[List[Any]] = []
    mch_lst.append(["Machine Architecture", pf.machine()])
    mch_lst.append(["Network Node Name", pf.node()])
    mch_lst.append(["Generic Platform Info", pf.platform()])
    mch_lst.append(["Processor Type", pf.processor()])
    mch_lst.append(["OS Release Version", pf.release()])
    mch_lst.append(["OS Name", pf.system()])
    mch_lst.append(["OS Version Info", pf.version()])

    if "linux" in CURRENT_PLATFORM:
        # pf.libc_ver() returns a tuple, convert to string
        mch_lst.append(["libc Version", str(pf.libc_ver())])
    elif "darwin" in CURRENT_PLATFORM:
        # Additional macOS specific info via sysctl
        try:
            # run_command returns bytes, so decode for int conversion
            memsize_bytes = int(run_command(["sysctl", "-n", "hw.memsize"]).decode("utf-8", errors="replace").strip())
            mch_lst.append(["RAM (GB)", f"{memsize_bytes / (1024**3):.2f}"])
        except Exception as e:
            mch_lst.append(["RAM (GB)", f"Error: {e}"])
        mch_lst.append(["CPUs", run_command(["sysctl", "-n", "hw.ncpu"]).decode("utf-8", errors="replace").strip()])
        mch_lst.append(["Active CPUs", run_command(["sysctl", "-n", "hw.activecpu"]).decode("utf-8", errors="replace").strip()])
        mch_lst.append(["Physical CPUs", run_command(["sysctl", "-n", "hw.physicalcpu"]).decode("utf-8", errors="replace").strip()])
        mch_lst.append(["Logical CPUs", run_command(["sysctl", "-n", "hw.logicalcpu"]).decode("utf-8", errors="replace").strip()])
        mch_lst.append(["Model", run_command(["sysctl", "-n", "hw.model"]).decode("utf-8", errors="replace").strip()])
    return tb.tabulate(mch_lst, headers=MCH_LST_HDR, tablefmt=TBLFMT)

def get_sys_info() -> str:
    """
    Gathers various Python 'sys' module related information.
    """
    sys_lst: List[List[Any]] = []
    sys_lst.append(["API Version", sys.api_version])
    sys_lst.append(["Command-line Arguments", sys.argv])
    sys_lst.append(["System Platform", sys.platform])
    sys_lst.append(["Platform Library Directory", sys.platlibdir])
    sys_lst.append(["Python Prefix", sys.prefix])
    sys_lst.append(["Pycache Prefix", sys.pycache_prefix])
    return tb.tabulate(sys_lst, headers=SYS_LST_HDR, tablefmt=TBLFMT)

def get_os_info() -> str:
    """
    Gathers various OS-level information using the 'os' module.
    """
    os_lst: List[List[Any]] = []
    os_lst.append(["Current User", os.environ.get("USER")])
    os_lst.append(["CPU Count", os.cpu_count()])
    # os.ctermid() is POSIX-specific and not available on Windows
    if hasattr(os, 'ctermid'):
        try:
            os_lst.append(["Controlling Terminal", os.ctermid()])
        except OSError:
            os_lst.append(["Controlling Terminal", "N/A (No controlling terminal)"])
    else:
        os_lst.append(["Controlling Terminal", "N/A (Not supported on this OS)"])
    os_lst.append(["Current Directory Indicator", os.curdir])
    os_lst.append(["Default Executable Path", os.defpath])
    os_lst.append(["Dev Null Path", os.devnull])
    os_lst.append(["Extension Separator", os.extsep])
    
    if "linux" in CURRENT_PLATFORM:
        try:
            # os.get_terminal_size() returns a os.terminal_size object, convert to string
            os_lst.append(["Terminal Size", str(os.get_terminal_size())])
        except OSError: # Raised if not connected to a TTY
            os_lst.append(["Terminal Size", "N/A (Not a terminal)"])
    os_lst.append(["Current Working Directory", os.getcwd()])
    os_lst.append(["OS Name (posix/nt)", os.name])
    return tb.tabulate(os_lst, headers=OS_LST_HDR, tablefmt=TBLFMT)

def get_arp_info() -> str:
    """
    Gathers ARP table information using 'arp -a' and processes it into a table.
    Handles differences in 'arp -a' output across Linux and macOS.
    """
    arp_table_data: List[List[str]] = []
    try:
        # print(f"DEBUG: Calling run_command for arp -a...") # Removed debug print
        # run_command returns bytes.
        arp_output_bytes = run_command(["arp", "-a"], shell=False, check=True) 
        # print(f"DEBUG: Type of arp_output_bytes: {type(arp_output_bytes)}") # Removed debug print
        
        arp_output_str = arp_output_bytes.decode("utf-8", errors="replace").strip()
        # print(f"DEBUG: Type of arp_output_str (decoded from bytes): {type(arp_output_str)}") # Removed debug print

        # Process output in Python instead of grep/awk
        for line in arp_output_str.splitlines():
            # Skip incomplete entries
            if "incomplete" in line:
                continue

            # Regex to parse ARP line
            # Common patterns:
            # Linux: Hostname (IP) at MAC [ether] on Interface
            # Darwin: Hostname (IP) at MAC on Interface [if_type]
            # Capture Name, IP, MAC, Interface
            match = re.search(r'^(\S+)\s+\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]+)(?:\s+\[ether\])?\s+on\s+(\S+)', line)
            
            if match:
                name = match.group(1).strip()
                ip4 = match.group(2).strip()
                mac = match.group(3).strip()
                interface = match.group(4).strip()
                arp_table_data.append([name, ip4, mac, interface])
            else:
                # Fallback for other formats or unparsed lines (e.g., Windows simplified, if not skipped above)
                # Windows 'arp -a' format is very different and often needs dedicated parsing.
                # Since win32 is explicitly skipped, this might catch unexpected formats on Linux/macOS
                parts = line.split()
                if len(parts) >= 4: # Basic check for enough parts
                    # This is a very generic fallback and might not always be correct.
                    # It tries to extract parts based on common order.
                    potential_name = parts[0].replace('?', 'unknown') # Replace '?' with 'unknown'
                    potential_ip = parts[1].replace('(', '').replace(')', '')
                    potential_mac = parts[3]
                    potential_iface = parts[-1] # Assuming interface is last for some formats

                    # Add a simple heuristic to avoid clearly invalid entries for now
                    if '.' in potential_ip and ':' in potential_mac:
                        arp_table_data.append([potential_name, potential_ip, potential_mac, potential_iface])
                    # elif dbg: # Removed debug print
                        # print(f"DEBUG: Line not matched by regex and fallback heuristic failed: {line}") # Removed debug print


    except FileNotFoundError as e:
        # print(f"DEBUG: Caught FileNotFoundError: {type(e)}, {e}") # Removed debug print
        return f"Error: Command not found to get ARP info ({e}). Please ensure 'arp' is installed."
    except subprocess.CalledProcessError as e:
        # print(f"DEBUG: Caught CalledProcessError: {type(e)}, {e}") # Removed debug print
        stderr_content = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
        output_content = e.output.decode("utf-8", errors="replace") if isinstance(e.output, bytes) else str(e.output)
        return f"Error running ARP command: Return Code: {e.returncode}, Stdout: {output_content}, Stderr: {stderr_content}"
    except Exception as e:
        # print(f"DEBUG: Caught generic Exception in get_arp_info: {type(e)}, {e}") # Removed debug print
        error_detail = ""
        if isinstance(e, subprocess.CalledProcessError):
            output = e.output.decode('utf-8', errors='replace') if isinstance(e.output, bytes) else str(e.output)
            stderr = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else str(e.stderr)
            error_detail = f"Command failed with code {e.returncode}. Output: {output}, Stderr: {stderr}"
        else:
            try:
                error_detail = str(e)
            except Exception as inner_e:
                error_detail = f"Failed to stringify exception: {type(e).__name__} object. Inner error: {inner_e}"
        
        return f"An unexpected error occurred getting ARP info: {error_detail}"

    return tb.tabulate(arp_table_data, headers=ARP_HDR, tablefmt=TBLFMT)

def get_win32_info() -> str:
    """
    Gathers Windows-specific platform information using 'platform' module functions.
    """
    win32_lst: List[List[str]] = []
    if "win32" in CURRENT_PLATFORM:
        win32_lst.append(["Windows Edition", pf.win32_edition()])
        win32_lst.append(["Is IoT Edition", str(pf.win32_is_iot())]) # Convert boolean to string
        win32_lst.append(["Windows Version", pf.win32_ver()])
    else:
        win32_lst.append(["N/A", "Not a Windows system"])
    return tb.tabulate(win32_lst, headers=STD_HDR, tablefmt=TBLFMT)

def get_linux_info() -> str:
    """
    Gathers Linux-specific OS release information from freedesktop.org standards.
    """
    lnx_lst: List[List[str]] = []
    if "linux" in CURRENT_PLATFORM:
        # pf.freedesktop_os_release() returns a dictionary
        lnx_lst = [[key, value] for key, value in pf.freedesktop_os_release().items()]
    else:
        lnx_lst.append(["N/A", "Not a Linux system"])
    return tb.tabulate(lnx_lst, headers=LNX_LST_HDR, tablefmt=TBLFMT)

# --- Main execution logic ---

async def main():
    """
    Main asynchronous function to orchestrate gathering and displaying system information.
    Handles user interaction, calls appropriate info-gathering functions, and writes to a file.
    """
    # Ensure the report output directory exists
    os.makedirs(report_output_dir, exist_ok=True) # exist_ok=True prevents error if dir already exists

    # Dynamically populate report_functions dictionary
    # Functions are stored as references, to be called when selected by the user.
    # The 'nmap' entry now points to the async version.
    report_functions: Dict[str, Any] = {
        "command line": get_cli_info,
        "python": get_pyt_info,
        "machine": get_mch_info,
        "arp": get_arp_info,
        "netifaces": get_ni_info,
        "system": get_sys_info,
        "os": get_os_info,
        "windows": get_win32_info,
        "linux": get_linux_info,
        "nmap": async_scan_network # This is now the async function
    }

    # Open the report file in write mode. It will be created if it doesn't exist, or truncated if it does.
    with open(full_report_filepath, 'w') as info_file:
        print("Available reports:")
        platform_reports = AVAILABLE_REPORTS.get(CURRENT_PLATFORM, [])
        for i, report in enumerate(platform_reports):
            print(f"{i + 1}. {report.replace('_', ' ').title()}") # Nicer display for report names

        report_choices_str = input("Enter the numbers of the reports you want to see (comma-separated): ")
        selected_report_indices: List[int] = []

        # Parse user input for report selection
        for choice in report_choices_str.split(","):
            try:
                index = int(choice.strip()) - 1
                if 0 <= index < len(platform_reports):
                    selected_report_indices.append(index)
                else:
                    print(f"Warning: Invalid choice '{choice.strip()}' - number out of range.")
            except ValueError:
                if choice.strip(): # Only warn if input wasn't just empty space
                    print(f"Warning: Invalid input '{choice.strip()}' - please enter numbers.")

        # Get the actual report names based on valid indices
        selected_reports_names = [platform_reports[i] for i in selected_report_indices]

        # Iterate through selected reports and generate their content
        for report_type in selected_reports_names:
            report_func = report_functions.get(report_type)
            if report_func:
                # if dbg: # Removed debug print
                    # print(f"\n--- Running report: {report_type.upper()} ---") # Removed debug print

                report_content: str
                try:
                    # Check if the function is a coroutine function (async) and await it
                    if asyncio.iscoroutinefunction(report_func):
                        report_content = await report_func()
                    else:
                        report_content = report_func() # Call synchronous function directly
                except Exception as e:
                    report_content = f"Error generating {report_type} report: {e}"
                    print(report_content) # Also print to console on error

                # if dbg: # Removed debug print
                    # print(report_content) # Removed debug print
                info_file.write(report_content)
                info_file.write("\n\n") # Add extra newlines for readability between reports

                # Platform-specific action: Text-to-speech on macOS
                if 'darwin' in CURRENT_PLATFORM:
                    try:
                        # Use subprocess.run for external command
                        subprocess.run(["say", "-v", "Moira", f"Generating {report_type} report"], check=True, capture_output=True)
                    except Exception as e:
                        print(f"Could not use 'say' command: {e}")
            else:
                print(f"Report type '{report_type}' not found or function missing.")

        # If debug mode is on, write environment variables to the report file
        # if dbg: # Removed debug print
            # env_vars = [[key, value] for key, value in os.environ.items()] # Removed debug print
            # env_table = tb.tabulate(env_vars, headers=STD_HDR, tablefmt=TBLFMT) # Removed debug print
            # info_file.write("\n--- Environment Variables ---") # Removed debug print
            # info_file.write("\n") # Removed debug print
            # info_file.write(env_table) # Removed debug print
            # info_file.write("\n") # Removed debug print

# Entry point of the script
if __name__ == "__main__":
    # Clear the console screen based on the operating system
    if "win32" in CURRENT_PLATFORM:
        subprocess.run("cls", shell=True)
    else:
        subprocess.run("clear", shell=True)

    # Run the main asynchronous function
    asyncio.run(main())

    # --- Open the generated report file ---
    open_command_args: Optional[List[str]] = None

    if "win32" in CURRENT_PLATFORM:
        open_command_args = ["notepad", full_report_filepath]
    elif "darwin" in CURRENT_PLATFORM:
        open_command_args = ["open", full_report_filepath]
    elif "linux" in CURRENT_PLATFORM:
        # On Linux, try xdg-open first, which intelligently opens the file
        # Fallback to printing a message if xdg-open is not found or fails
        try:
            subprocess.run(["xdg-open", full_report_filepath], check=True, capture_output=True)
            print(f"Report opened with xdg-open: {full_report_filepath}")
            sys.exit(0) # Exit successfully after opening
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            print(f"Warning: xdg-open not found or failed to open report automatically: {e}")
            print(f"Please check the report manually at: {full_report_filepath}")
            sys.exit(0) # Exit successfully, as manual check is an option

    if open_command_args:
        try:
            # Execute the command to open the report file
            subprocess.run(open_command_args, check=True)
        except Exception as e:
            print(f"Error opening report file automatically: {e}")
            print(f"Report saved to: {full_report_filepath}")
    else:
        print(f"Report saved to: {full_report_filepath}")

#!/usr/bin/env python3

# Import standard library modules
import os
import sys
import platform as pf
import subprocess
import re
import asyncio # For asynchronous operations
from typing import List, Dict, Any, Tuple, Optional

original_user_home = os.path.expanduser(f"~{os.getenv('SUDO_USER')}") if os.getenv('SUDO_USER') else os.path.expanduser('~')
sys.path.insert(0, os.path.join(original_user_home, 'dev'))

# only listing these as a reminder of what is usable - one day I will revert this to just import netwk and update the code appropriately
from netwk import (
   get_private_ipv4,
   get_public_ip,
   get_gateway_ip,
   get_ipv6_addresses,
   get_mac_address,
   get_open_tcp_ports,
   get_open_udp_ports,
   get_nwkset_data,
   get_ipconfig_data,
)

CURRENT_PLATFORM = sys.platform

try:
     import tabulate as tb
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "-q"])
    import tabulate as tb

if "win32" in CURRENT_PLATFORM:
    report_output_dir = "" # Current directory on Windows
else:
    report_output_dir = "/tmp/" # Standard temporary directory on Linux/macOS
report_file_name = "platinfo.txt"
full_report_filepath = os.path.join(report_output_dir, report_file_name)

# Define headers for tabular output using 'tabulate'
def crt_hdr(title, total_width=30, fill_char='-'):
    return title.center(total_width, fill_char)

NI_LST_HDR = [crt_hdr("netifaces"), ""]
PYT_LST_HDR = [crt_hdr("python info"), ""]
MCH_LST_HDR = [crt_hdr("machine info"), ""]
SYS_LST_HDR = [crt_hdr("sys"), ""]
OS_LST_HDR = [crt_hdr("os"), ""]
CLI_LST_HDR = [crt_hdr("CLI commands"), ""]
LNX_LST_HDR = [crt_hdr("linux details"), ""]
ARP_HDR = ["Name", "IP4", "MAC", "Interface"] # Corrected "name" to "Name" for consistency
SN_HDR = ["Hostname", "IP Address", "Port", "Service"]
STD_HDR = ["Key", "Value"]
TBLFMT = "rounded_outline" # Table format for tabulate

# Dictionary mapping platforms to available report types
core_reports = ["command line", "python", "machine", "system", "os"]
AVAILABLE_REPORTS: Dict[str, List[str]] = {
    "darwin": core_reports + ["arp", "netifaces", "nmap"],
    "linux": core_reports + ["arp", "netifaces", "linux", "nmap"],
    "win32": core_reports + ["windows"]
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
        gateway_ip = get_gateway_ip()
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

    # see oldmaclid.py for the old code - this is much cleaner
    if "darwin" in CURRENT_PLATFORM:
        cli_lst.append(["hostname", run_command(["hostname"]).decode("utf-8", errors="replace").strip()])

        cli_lst += get_nwkset_data(CURRENT_PLATFORM)
        cli_lst += get_ipconfig_data(CURRENT_PLATFORM)
        for line in subprocess.run(["sw_vers"], capture_output=True, text=True).stdout.splitlines():
            cli_lst.append([line.strip().split(":", 1)[0].strip(), line.strip().split(":", 1)[1].strip()])
        
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
    
    if "win32" != CURRENT_PLATFORM:
        for opt in ["m", "n", "o", "p", "r", "s", "v"]:
            cli_lst.append([f"uname -{opt}", run_command(["uname", f"-{opt}"]).decode("utf-8", errors="replace").strip()]) # Label improved

    return tb.tabulate(cli_lst, headers=CLI_LST_HDR, tablefmt=TBLFMT)

def get_ni_info() -> str:
    ni_lst: List[List[str]] = []
    ni_lst.append(["Gateway IP", get_gateway_ip()])
    ni_lst.append(["Local IP4 Address", get_private_ipv4()])
    ni_lst.append(["Public IP4 Address", get_public_ip()])
    for x in get_ipv6_addresses():
        ni_lst.append(["IP6 Addresses", x])
    ni_lst.append(["MAC Address", get_mac_address()])

    return tb.tabulate(ni_lst, headers=NI_LST_HDR, tablefmt=TBLFMT)

def get_pyt_info() -> str:
    pyt_lst: List[List[str]] = []
    pyt_lst.append(["Branch", pf.python_branch()])
    for x in pf.python_build():
        pyt_lst.append(["Build", x]) 
    pyt_lst.append(["Build", str(pf.python_build())])
    pyt_lst.append(["Compiler", pf.python_compiler()])
    pyt_lst.append(["Implementation", pf.python_implementation()])
    pyt_lst.append(["Revision", pf.python_revision()])
    pyt_lst.append(["Python Version", pf.python_version()])
    for k, v in pf.uname()._asdict().items():
        pyt_lst.append([k.replace('_', ' ').title(), v])

    return tb.tabulate(pyt_lst, headers=PYT_LST_HDR, tablefmt=TBLFMT)

def get_mch_info() -> str:
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
    sys_lst: List[List[Any]] = []
    sys_lst.append(["API Version", sys.api_version])
    sys_lst.append(["Command-line Arguments", sys.argv])
    sys_lst.append(["System Platform", sys.platform])
    sys_lst.append(["Platform Library Directory", sys.platlibdir])
    sys_lst.append(["Python Prefix", sys.prefix])
    sys_lst.append(["Pycache Prefix", sys.pycache_prefix])
    return tb.tabulate(sys_lst, headers=SYS_LST_HDR, tablefmt=TBLFMT)

def get_os_info() -> str:
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
    arp_table_data: List[List[str]] = []
    try:
        arp_output_bytes = run_command(["arp", "-a"], shell=False, check=True) 
        arp_output_str = arp_output_bytes.decode("utf-8", errors="replace").strip()
        for line in arp_output_str.splitlines():
            if "incomplete" in line:
                continue

            match = re.search(r'^(\S+)\s+\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]+)(?:\s+\[ether\])?\s+on\s+(\S+)', line)
            
            if match:
                name = match.group(1).strip()
                ip4 = match.group(2).strip()
                mac = match.group(3).strip()
                interface = match.group(4).strip()
                arp_table_data.append([name, ip4, mac, interface])
            else:
                parts = line.split()
                if len(parts) >= 4: # Basic check for enough parts
                    potential_name = parts[0].replace('?', 'unknown') # Replace '?' with 'unknown'
                    potential_ip = parts[1].replace('(', '').replace(')', '')
                    potential_mac = parts[3]
                    potential_iface = parts[-1] # Assuming interface is last for some formats

                    if '.' in potential_ip and ':' in potential_mac:
                        arp_table_data.append([potential_name, potential_ip, potential_mac, potential_iface])

    except FileNotFoundError as e:
        return f"Error: Command not found to get ARP info ({e}). Please ensure 'arp' is installed."
    except subprocess.CalledProcessError as e:
        stderr_content = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
        output_content = e.output.decode("utf-8", errors="replace") if isinstance(e.output, bytes) else str(e.output)
        return f"Error running ARP command: Return Code: {e.returncode}, Stdout: {output_content}, Stderr: {stderr_content}"
    except Exception as e:
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
    lnx_lst: List[List[str]] = []
    if "linux" in CURRENT_PLATFORM:
        # pf.freedesktop_os_release() returns a dictionary
        lnx_lst = [[key, value] for key, value in pf.freedesktop_os_release().items()]
    else:
        lnx_lst.append(["N/A", "Not a Linux system"])
    return tb.tabulate(lnx_lst, headers=LNX_LST_HDR, tablefmt=TBLFMT)

# --- Main execution logic ---
async def main():
    os.makedirs(report_output_dir, exist_ok=True)
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
        "nmap": async_scan_network
    }

    with open(full_report_filepath, 'w') as info_file:
        print("Available reports:")
        platform_reports = AVAILABLE_REPORTS.get(CURRENT_PLATFORM, [])
        for i, report in enumerate(platform_reports):
            print(f"{i + 1}. {report.replace('_', ' ').title()}") # Nicer display for report names

        report_choices_str = input("Enter the numbers of the reports you want to see (comma-separated): ")
        selected_report_indices: List[int] = []

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
        selected_reports_names = [platform_reports[i] for i in selected_report_indices]
        for report_type in selected_reports_names:
            report_func = report_functions.get(report_type)
            if report_func:
                report_content: str
                try:
                    if asyncio.iscoroutinefunction(report_func):
                        report_content = await report_func()
                    else:
                        report_content = report_func() # Call synchronous function directly
                except Exception as e:
                    report_content = f"Error generating {report_type} report: {e}"
                    print(report_content) # Also print to console on error

                info_file.write(report_content)
                info_file.write("\n\n") # Add extra newlines for readability between reports

                if 'darwin' in CURRENT_PLATFORM:
                    try:
                        subprocess.run(["say", "-v", "Moira", f"Generating {report_type} report"], check=True, capture_output=True)
                    except Exception as e:
                        print(f"Could not use 'say' command: {e}")
            else:
                print(f"Report type '{report_type}' not found or function missing.")

if __name__ == "__main__":
    if "win32" in CURRENT_PLATFORM:
        subprocess.run("cls", shell=True)
    else:
        subprocess.run("clear", shell=True)
    asyncio.run(main())

    open_command_args: Optional[List[str]] = None

    if "win32" in CURRENT_PLATFORM:
        open_command_args = ["notepad", full_report_filepath]
    elif "darwin" in CURRENT_PLATFORM:
        open_command_args = ["open", full_report_filepath]
    elif "linux" in CURRENT_PLATFORM:
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
            subprocess.run(open_command_args, check=True)
        except Exception as e:
            print(f"Error opening report file automatically: {e}")
            print(f"Report saved to: {full_report_filepath}")
    else:
        print(f"Report saved to: {full_report_filepath}")

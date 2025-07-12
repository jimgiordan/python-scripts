#!/usr/bin/env python3

#import stdlib modules
import os, sys, platform as pf, subprocess, re

spf = sys.platform

#import installed modules
try:
    import netifaces as ni
    import tabulate as tb
except:
    if "linux" in spf:
        os.system("sudo apt install python3-netifaces python3-tabulate -y")
    else:
        os.system( "pip3 install netifaces tabulate" )
    import netifaces as ni
    import tabulate as tb

## initialisation bits
dbg = False
# csc = False #change to True to muck around with the .ssh/config file

if "win32" not in spf:
    report_path = "/tmp/"
else:
    report_path = ""
report_file = "pfinf.txt"

ni_lst_hdr = [ "--- netifaces ---  ", "" ]
pyt_lst_hdr = [ "---python info --- ", "" ]
mch_lst_hdr = [ "---machine info--- ", "" ]
sys_lst_hdr = [ "  ---  sys  ---    ", "" ]
os_lst_hdr = [ "   ---  os  ---    ", "" ]
cli_lst_hdr = [ "---CLI commands ---", "" ]
lnx_lst_hdr = [ "---linux details---", "" ]
arp_hdr = [ "name", "ip4", "MAC", "interface"]
sn_hdr = ["Hostname", "IP Address", "Port", "Service"]
std_hdr = [ "Key", "Value" ]
tblfmt = "rounded_outline"

available_reports = {
    "darwin": [ "command line", "python", "machine", "arp", "netifaces", "system", "os", "nmap" ],
    "linux": [ "command line", "python", "machine", "arp", "netifaces", "system", "os", "linux", "nmap" ],
    "win32": [ "command line", "python", "machine", "system", "os", "windows" ]
}
## initialisation done

def run_cmd(cmd):
    return subprocess.check_output( cmd, shell=True ).decode().strip()

def scan_network():
    gw = ni.gateways()["default"][ni.AF_INET][0] + "/24"
    output = run_cmd( f"nmap -T5 -oG - {gw}" ).splitlines()
    sn_lst = []
    for line in output:
        match = re.search( r'Host: (.*?) \((.*?)\)\s+Ports: (.*)', line )
        if match:
            ip_address = match.group(1).strip()  
            hostname = match.group(2).strip()
            ports_str = match.group(3).strip()

            ports = re.findall( r'(\d+)/open/tcp//([^/]*)/', ports_str )  
            for port, service in ports:
                sn_lst.append( [hostname, ip_address, port, service] )

    return tb.tabulate( sn_lst, headers=sn_hdr, tablefmt=tblfmt )

def get_cli_info():
## use of netifaces should make this redundant - left here for potential multi platfrom issues
## win32 appears to have visual studio dependancies for netifaces 
    cli_lst = []
    # Network details
    if "darwin" in spf:  # macOSrun_command("say ooh you want the command line options?")
        cli_lst.append( [ "gateway", run_cmd( "ipconfig getoption en0 router" ) ] )
        cli_lst.append( [ "ip4", run_cmd( "ipconfig getifaddr en0" ) ] )
        cli_lst.append( [ "alt_cmd ip4", run_cmd("scutil --nwi | grep address | awk '{print $3}'" ) ] )
        cli_lst.append( [ "ip6", run_cmd( "ifconfig en0 | grep inet6 | grep -v temp | awk '{print $2}'" ) ] )
        cli_lst.append( [ "sw_vers PN", run_cmd( "sw_vers -productName" ) ] )
        cli_lst.append( [ "sw_vers PV", run_cmd( "sw_vers -productVersion" ) ] )
        cli_lst.append( [ "hostname", run_cmd( "hostname" ) ] )

        for opt in [ "m", "n", "o", "p", "r", "s", "v" ]:
            cli_lst.append( [ opt + ":", run_cmd( f"uname -{opt}" ) ] )

    elif "linux" in spf:
        try:
            default_interface = run_cmd("ip route | awk '/default/ { print $5 }'")
        except subprocess.CalledProcessError:
            default_interface = "eth0"  
        cli_lst.append(["gateway", run_cmd(f"ip route show dev {default_interface} | awk '/default via/ {{print $3}}'")])
        cli_lst.append(["ip4", run_cmd(f"ip addr show {default_interface} | grep 'inet\\b' | awk '{{print $2}}' | cut -d/ -f1")])
        cli_lst.append(["ip6", run_cmd(f"ip addr show {default_interface} | grep 'inet6\\b' | awk '{{print $2}}' | cut -d/ -f1")])
        for opt in ["m", "n", "o", "p", "r", "s", "v"]:
            cli_lst.append( [ opt + ":", run_cmd( f"uname -{opt}" ) ] )
    else:
        cli_lst.append( ["gateway", rub_cmd("ipconfig | findstr /i \"Default Gateway\" | findstr /V 255.255.255.0") ])  #To be refined, extract IP after :
        cli_lst.append( ["ip4", run_cmd("ipconfig | findstr IPv4") ] ) #To be refined, extract IP after :
        cli_lst.append( ["systeminfo"] ) 
    return tb.tabulate( cli_lst, headers=cli_lst_hdr, tablefmt=tblfmt )

"""
def chng_ssh_cnfg():
## add root user to all ssh connection attempts & setup an alias to ssh the gateway
    if os.path.isdir( os.path.expanduser( "~/.ssh" ) ):
        if os.path.isfile( os.path.expanduser( "~/.ssh/config" ) ):
            os.system( "cat ~/.ssh/config >> ~/.ssh/config.orig" )
            os.remove( os.path.expanduser( "~/.ssh/config" ) )
            os.system( "echo 'Host * \n\tUser root\n\nHost gw\n\tHostName 192.168.1.1' >> ~/.ssh/config" )
            if dbg is not False:
                os.system( "open ~/.ssh/config" )
    else:
        os.mkdir( os.path.expanduser( "~/.ssh" ) )
        os.system( "touch ~/.ssh/config" )
        os.system( "echo 'Host * \n\tUser root' >> ~/.ssh/config" )
        os.system( "open ~/.ssh/config" )
"""
def get_ni_info():
    ni_lst=[]
    interface = ni.gateways()["default"][ni.AF_INET][1]
    ni_lst.append( ["gateway address", ni.gateways()["default"][ni.AF_INET][0]] )
    ni_lst.append( ["ipv4 address", ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]] )
    ni_lst.append( ["ipv6 address", ni.ifaddresses(interface)[ni.AF_INET6][0]["addr"]] )
    ni_lst.append( ["mac address", ni.ifaddresses(interface)[ni.AF_LINK][0]["addr"]] )
    return tb.tabulate( ni_lst, headers=ni_lst_hdr, tablefmt=tblfmt ) 

def get_pyt_info():
    pyt_lst = []
    pyt_lst.append( ["branch", pf.python_branch()] )
    pyt_lst.append( ["build", pf.python_build()] )
    pyt_lst.append( ["compiler", pf.python_compiler()] )
    pyt_lst.append( ["implementation", pf.python_implementation()] )
    pyt_lst.append( ["revision", pf.python_revision()] )
    pyt_lst.append( ["python version", pf.python_version()] )
    return tb.tabulate( pyt_lst, headers=pyt_lst_hdr, tablefmt=tblfmt )

def get_mch_info():
    mch_lst = []
    mch_lst.append( ["machine", pf.machine()] )
    mch_lst.append( ["node", pf.node()] )
    mch_lst.append( ["platform", pf.platform()] )
    mch_lst.append( ["processor", pf.processor()] )
    mch_lst.append( ["release", pf.release()] )
    mch_lst.append( ["system", pf.system()] )
    mch_lst.append( ["version", pf.version()] )
    if "linux" in spf:
        mch_lst.append( ["libc_ver", pf.libc_ver()] )
    elif "darwin" in spf:
        mch_lst.append(["RAM", int(run_cmd(f"sysctl -n hw.memsize")) / (1024**3) ])
        mch_lst.append(["CPUs", run_cmd(f"sysctl -n hw.ncpu")])
        mch_lst.append(["Active CPUs", run_cmd(f"sysctl -n hw.activecpu")])
        mch_lst.append(["Physical CPUs", run_cmd(f"sysctl -n hw.physicalcpu")])
        mch_lst.append(["Logical CPUs", run_cmd(f"sysctl -n hw.logicalcpu")])
        mch_lst.append(["Model", run_cmd(f"sysctl -n hw.model")])        
    return tb.tabulate( mch_lst, headers=mch_lst_hdr, tablefmt=tblfmt )

def get_sys_info():
    sys_lst=[]
    sys_lst.append( ["api_version", sys.api_version] )
    sys_lst.append( ["argv", sys.argv] )
    sys_lst.append( ["sys.platform", sys.platform] )
    sys_lst.append( ["platlibdir", sys.platlibdir] )
    sys_lst.append( ["prefix", sys.prefix] )
    sys_lst.append([ "pycache_prefix", sys.pycache_prefix] )
    return tb.tabulate( sys_lst, headers=sys_lst_hdr, tablefmt=tblfmt )

def get_os_info():
    os_lst = []
    os_lst.append( ["user", os.environ.get( "USER" )] )
    os_lst.append( ["cpu_count", os.cpu_count()] )
    os_lst.append( ["ctermid", os.ctermid()]) 
    os_lst.append( ["curdir", os.curdir] )  
    os_lst.append( ["defpath", os.defpath] )
    os_lst.append( ["devnull", os.devnull] )
    os_lst.append( ["extsep", os.extsep] )
    ##info["get_exec_path"] = os.get_exec_path()
    if "linux" in spf:
        os_lst.append(["get_terminal_size", os.get_terminal_size()])
    os_lst.append( ["getcwd", os.getcwd()] )
    os_lst.append( ["name", os.name] )
    return tb.tabulate( os_lst, headers=os_lst_hdr, tablefmt=tblfmt )

def get_arp_info():
    if "linux" in spf:
        arp_output = os.popen("arp -a | grep -v incomplete | awk '{print $1, $2, $4, $7}'").read()
    else:
        arp_output = os.popen("arp -a | grep -v incomplete | awk '{print $1, $2, $4, $6}'").read()
    arp_output = arp_output.replace("(", "").replace(")", "")
    arp_table = [line.split() for line in arp_output.splitlines()]
    return tb.tabulate( arp_table, headers=arp_hdr, tablefmt=tblfmt )

""" stuff to integrate if i want to use on iOS or android
info["ios_ver"] = pf.ios_ver()
for i in range( len( pf.android_ver() ) ):
    info["android_ver"+ str(i)+ ""] = pf.android_ver()[i]
"""

def get_win32_info():
    win32_lst = []
    win32_lst.append( ["win32_edition", pf.win32_edition()] )
    win32_lst.append( ["win32_is_iot", pf.win32_is_iot()] )
    win32_lst.append( ["win32_ver", pf.win32_ver()] )
    return tb.tabulate( win32_lst, headers=std_hdr, tablefmt=tblfmt )

def get_linux_info():
    if "linux" in spf:
        lnx_lst = [ [key, value] for key, value in pf.freedesktop_os_release().items() ]
        return tb.tabulate( lnx_lst, headers=lnx_lst_hdr, tablefmt=tblfmt )

if os.path.isfile( report_path+report_file ):
    pass
else:
    os.system( "touch "+report_path+report_file )

report_functions = {
    "command line": get_cli_info(),
    "python": get_pyt_info(),
    "machine": get_mch_info(),
    "arp": get_arp_info(),
    "netifaces": get_ni_info(),
    "system": get_sys_info(),
    "os": get_os_info(),
    "windows": get_win32_info(),
    "linux": get_linux_info(),
    "nmap": scan_network()
}

def main():
    with open( report_path+report_file, 'w' ) as info_file:
    
## display available report options
        print("Available reports:" )
        for i, report in enumerate( available_reports.get( sys.platform, [] ) ):
            print( f"{i + 1}. {report}" )

## get user report selection
        report_choices = input("Enter the numbers of the reports you want to see (comma-separated): ")
        selected_reports = [ available_reports[ sys.platform ][int( choice ) - 1] for choice in report_choices.split( "," ) if choice.strip() ]

## display selected reports in the order selected
        for report_type in selected_reports:
            report_function = report_functions.get( report_type )
            if report_function:
                if dbg is not False:
                    print( report_function )
                info_file.write( report_function )
                info_file.write( "\n" )
                if 'darwin' in spf:
                    run_cmd("say -v Moira "+report_type)
            else:
                print(f"Report type '{report_type}' not found.")

        if dbg is not False: #the path environ value is so big it isn't worth looking at like this
            info_file.write( tb.tabulate( [[key, value] for key, value in os.environ.items()], headers=std_hdr, tablefmt=tblfmt))

if __name__ == "__main__":
    os.system( "clear" )
    main()

if "win32" in spf:
    cmd = "notepad "
elif "darwin" in spf:
    cmd = "open "
elif "linux" in spf:
    cmd = "xdg-open "
else:
    print("unknown system cannot open the report")
"""
if csc is not False:
    chng_ssh_cnfg()
"""
os.system( cmd+report_path+report_file )

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

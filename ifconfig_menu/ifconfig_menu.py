

import subprocess

def main():
    try:
        # Execute ipconfig and capture its output
        result = subprocess.run(["ipconfig", "getiflist"], capture_output=True, text=True, check=True)
        ipconfig_output = result.stdout
        print("ipconfig output:\n", ipconfig_output)

        # Parse ipconfig output to get interface names
        interfaces = ipconfig_output.strip().split()

        if not interfaces:
            print("No network interfaces found.")
            return

        print("\nAvailable network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i + 1}. {iface}")

        while True:
            try:
                choice = input("Select an interface by number (or 'q' to quit): ")
                if choice.lower() == 'q':
                    print("Exiting.")
                    return
                
                selected_index = int(choice) - 1
                if 0 <= selected_index < len(interfaces):
                    selected_interface = interfaces[selected_index]
                    print(f"You selected: {selected_interface}")

                    ipconfig_commands = {
                        "1": {"cmd": ["getifaddr", selected_interface], "desc": "Get IP address"},
                        "2": {"cmd": ["getoption"], "desc": "Get option (requires option-name or option-code)"},
                        "3": {"cmd": ["getpacket", selected_interface], "desc": "Get packet information"},
                        "4": {"cmd": ["getv6packet", selected_interface], "desc": "Get IPv6 packet information"},
                        "5": {"cmd": ["getra", selected_interface], "desc": "Get Router Advertisement information"},
                        "6": {"cmd": ["getsummary", selected_interface], "desc": "Get summary information"},
                        "7": {"cmd": ["getdhcpduid"], "desc": "Get DHCP DUID"},
                        "8": {"cmd": ["getdhcpiaid", selected_interface], "desc": "Get DHCP IAID"}
                    }

                    print("\nAvailable ipconfig commands for", selected_interface, ":")
                    for key, value in ipconfig_commands.items():
                        print(f"{key}. {value['desc']}")
                    print("q. Back to interface selection")

                    while True:
                        cmd_choice = input("Select a command by number (or 'q' to go back): ")
                        if cmd_choice.lower() == 'q':
                            break # Break from inner loop (command selection)
                        
                        if cmd_choice in ipconfig_commands:
                            if cmd_choice == "2":
                                option_name_or_code = input("Enter option-name or option-code: ")
                                command_to_execute = ["ipconfig", "getoption", selected_interface, option_name_or_code]
                            else:
                                command_to_execute = ["ipconfig"] + ipconfig_commands[cmd_choice]["cmd"]
                            try:
                                command_output = subprocess.run(command_to_execute, capture_output=True, text=True, check=True).stdout
                                command_str = ' '.join(command_to_execute)
                                print(f"\n--- Output for {command_str} ---")
                                print(command_output)
                            except subprocess.CalledProcessError as e:
                                print(f"Error executing {' '.join(command_to_execute)}: {e}")
                                print(f"Stderr: {e.stderr}")
                        else:
                            print("Invalid command choice. Please try again.")
                    # If the inner loop broke because 'q' was entered, we need to break the outer loop too.
                    if cmd_choice.lower() == 'q':
                        break
                    # If a command was executed, we want to go back to interface selection, so continue the outer loop.
                    continue
                else:
                    print("Invalid number. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number or 'q'.")

    except FileNotFoundError:
        print("Error: 'ipconfig' command not found. Please ensure it is installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing ipconfig: {e}")
        print(f"Stderr: {e.stderr}")

if __name__ == "__main__":
    main()


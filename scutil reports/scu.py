#!/usr/bin/env python3

import subprocess
import sys
import re
import math
import os
import platform

try:
    from tabulate import tabulate
except ImportError:
    print("Error: The 'tabulate' library is not installed.", file=sys.stderr)
    print("Please install it using: pip install tabulate", file=sys.stderr)
    sys.exit(1)

# --- Constants ---
# No REPORT_PREFIXES needed for scutil as we define display names
EST_COLUMN_CONTENT_WIDTH = 30 # scutil keys/values might be a bit longer
TABULATE_PADDING_WIDTH = 4
MIN_COLUMN_WIDTH = EST_COLUMN_CONTENT_WIDTH + TABULATE_PADDING_WIDTH

# --- Helper Functions ---
def get_scutil_queries():
    """
    Returns a hardcoded dictionary of common scutil --get keys to query.
    Keys are display names, values are the actual scutil key strings.
    """
    return {
        "Computer Name": "ComputerName",
        "Local Host Name": "LocalHostName",
        "Network Host Name": "HostName",
        "DNS Servers": "DNS",
        "Primary Network Interface (ID)": "PrimaryInterface",
        "Global IPv4 State": "State:/Network/Global/IPv4",
        "Global IPv6 State": "State:/Network/Global/IPv6",
        "Router IP Address": "State:/Network/Global/DNS/Router", # Might not always exist
        "Wi-Fi Power": "State:/Network/Interface/en0/AirPort/Power" # Assumes en0 is Wi-Fi
    }

def display_and_select_reports(available_queries_map):
    """
    Displays available scutil queries to the user in columns and gets their selection.

    Args:
        available_queries_map (dict): A dictionary where keys are user-friendly
                                      display names and values are the scutil key strings.

    Returns:
        list: A list of selected scutil key strings.
              Returns an empty list if no queries are available or invalid input.
    """
    if not available_queries_map:
        print("No scutil queries available to display.", file=sys.stderr)
        return []

    print("\n--- Available scutil Queries ---")

    display_name_map_index_to_key = {} # Maps "1" -> "ComputerName"
    display_items_for_tabulate = [] # List to hold formatted strings for multi-column display

    # Sort queries by display name for consistent numbering
    sorted_display_names = sorted(available_queries_map.keys())

    for i, display_name in enumerate(sorted_display_names):
        scutil_key = available_queries_map[display_name]
        display_name_map_index_to_key[str(i + 1)] = scutil_key
        display_items_for_tabulate.append(f"{i + 1}. {display_name}")

    try:
        terminal_width = os.get_terminal_size().columns
        calculated_num_columns = max(1, terminal_width // MIN_COLUMN_WIDTH)
    except OSError:
        calculated_num_columns = 3
    num_columns = calculated_num_columns

    num_items = len(display_items_for_tabulate)
    num_rows = math.ceil(num_items / num_columns)

    table_data = [['' for _ in range(num_columns)] for _ in range(int(num_rows))]

    for i, item_str in enumerate(display_items_for_tabulate):
        col_index = i // num_rows
        row_index = i % num_rows

        if col_index < num_columns:
            table_data[row_index][col_index] = item_str

    print(tabulate(table_data, tablefmt="plain"))

    print("-" * 40)

    while True:
        selection = input("Enter query numbers (comma-separated), 'all', or 'q' to quit: ").strip().lower()

        if selection == 'q':
            return []
        elif selection == 'all':
            return list(available_queries_map.values()) # Return all scutil key strings
        else:
            selected_scutil_keys = []
            invalid_choices = []
            choices = [c.strip() for c in selection.split(',') if c.strip()]

            for choice in choices:
                if choice in display_name_map_index_to_key:
                    selected_scutil_keys.append(display_name_map_index_to_key[choice])
                else:
                    invalid_choices.append(choice)

            if invalid_choices:
                print(f"Warning: Invalid query numbers ignored: {', '.join(invalid_choices)}. Please try again.", file=sys.stderr)
            if selected_scutil_keys:
                return selected_scutil_keys
            else:
                print("No valid queries selected. Please enter valid numbers, 'all', or 'q'.", file=sys.stderr)


def print_scutil_report(scutil_key):
    """
    Prints the report for a given scutil key.
    """
    print(f"\n--- scutil Query: {scutil_key} ---")
    try:
        # scutil --get returns non-zero if the key doesn't exist, but we still want to read stderr.
        result = subprocess.run(
            ["scutil", "--get", scutil_key],
            capture_output=True,
            text=True,
            check=False # Do not raise an exception for non-zero exit codes
        )
        output = result.stdout.strip()
        error_output = result.stderr.strip()

        if result.returncode != 0:
            if "No such key" in error_output:
                print(f"Key '{scutil_key}' not found or no value for this system/network state.")
            else:
                print(f"Error executing 'scutil --get {scutil_key}': {error_output}")
        else:
            print(output)

    except FileNotFoundError:
        print("Error: 'scutil' command not found. This script requires macOS.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred while querying '{scutil_key}': {e}", file=sys.stderr)

# --- Main Execution ---
def main():
    """
    Main function to orchestrate query retrieval, user interaction, and printing.
    """
    if platform.system() != "Darwin":
        print(f"Error: This script is designed for macOS only.", file=sys.stderr)
        print(f"Detected OS: {platform.system()}", file=sys.stderr)
        sys.exit(1)

    scutil_queries_map = get_scutil_queries() # Get the hardcoded map of queries

    if not scutil_queries_map:
        print("Exiting as no scutil queries are defined.", file=sys.stderr)
        sys.exit(1)

    selected_scutil_keys = display_and_select_reports(scutil_queries_map)

    if not selected_scutil_keys:
        print("No queries selected. Exiting.")
        sys.exit(0)

    for scutil_key in selected_scutil_keys:
        print_scutil_report(scutil_key) # Call the scutil-specific print function

if __name__ == "__main__":
    main()

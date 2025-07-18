#!/usr/bin/env python3

import subprocess
import sys
import re
import math
import os
import platform # NEW: Import the platform module

try:
    from tabulate import tabulate
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "-q"])
    from tabulate import tabulate

# --- Constants ---
REPORT_PREFIXES = ("SP", "DataType")
EST_COLUMN_CONTENT_WIDTH = 25
TABULATE_PADDING_WIDTH = 4
MIN_COLUMN_WIDTH = EST_COLUMN_CONTENT_WIDTH + TABULATE_PADDING_WIDTH

# --- Helper Functions ---
def get_system_profiler_reports():
    """
    Retrieves a list of available report data types from system_profiler.
    """
    # Note: The OS check is now primarily in main(), but FileNotFoundError
    # for 'system_profiler' is still handled here as a fallback.
    try:
        result = subprocess.run(
            ["system_profiler", "-listDataTypes"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        report_names = re.findall(r"^\s*(\S+)\s*$", output, re.MULTILINE)
        return report_names

    except FileNotFoundError:
        print("Error: 'system_profiler' command not found. This typically means you are not on macOS or the command is not in your PATH.", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error listing reports: {e.stderr.strip()}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return []

def display_and_select_reports(available_reports):
    """
    Displays available reports to the user in columns and gets their selection.
    """
    if not available_reports:
        print("No reports available to display.", file=sys.stderr)
        return [], {}

    print("\n--- Available System Profiler Reports ---")

    display_name_map = {}
    display_items_for_tabulate = []

    for i, report_name in enumerate(available_reports):
        display_name = report_name
        for prefix in REPORT_PREFIXES:
            display_name = display_name.replace(prefix, "")

        display_name_map[str(i + 1)] = report_name
        display_items_for_tabulate.append(f"{i + 1}. {display_name.strip()}")

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
        selection = input("Enter report numbers (comma-separated), 'all', or 'q' to quit: ").strip().lower()

        if selection == 'q':
            return [], {}
        elif selection == 'all':
            return available_reports, display_name_map
        else:
            selected_raw_names = []
            invalid_choices = []
            choices = [c.strip() for c in selection.split(',') if c.strip()]

            for choice in choices:
                if choice in display_name_map:
                    selected_raw_names.append(display_name_map[choice])
                else:
                    invalid_choices.append(choice)

            if invalid_choices:
                print(f"Warning: Invalid report numbers ignored: {', '.join(invalid_choices)}. Please try again.", file=sys.stderr)
            if selected_raw_names:
                return selected_raw_names, display_name_map
            else:
                print("No valid reports selected. Please enter valid numbers, 'all', or 'q'.", file=sys.stderr)


def print_report(report_name):
    """
    Prints the system_profiler report for a given data type.
    """
    print(f"\n--- Report: {report_name} ---")
    try:
        result = subprocess.run(
            ["system_profiler", report_name],
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout.strip())
    except FileNotFoundError:
        print(f"Error: 'system_profiler' command not found when trying to get '{report_name}'. This usually means you are not on macOS or the command is not in your PATH.", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Error printing report '{report_name}': {e.stderr.strip()}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred while printing '{report_name}': {e}", file=sys.stderr)

# --- Main Execution ---
def main():
    """
    Main function to orchestrate report retrieval, user interaction, and printing.
    """
    # NEW: OS check at the very beginning of the main function
    if platform.system() != "Darwin": # 'Darwin' is the system name for macOS
        print(f"Error: This script is designed for macOS only.", file=sys.stderr)
        print(f"Detected OS: {platform.system()}", file=sys.stderr)
        sys.exit(1)

    available_reports = get_system_profiler_reports()

    if not available_reports:
        print("Exiting as no system profiler reports could be found.", file=sys.stderr)
        sys.exit(1)

    selected_reports_to_print, _ = display_and_select_reports(available_reports)

    if not selected_reports_to_print:
        print("No reports selected. Exiting.")
        sys.exit(0)

    for report_name in selected_reports_to_print:
        print(report_name)
        print_report(report_name)

    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "tabulate", "-y", "-q"])    

if __name__ == "__main__":
    main()

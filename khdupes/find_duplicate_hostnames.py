#!/usr/bin/env python3

import collections
import subprocess
import sys

try:
    from tabulate import tabulate
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "-q"])
    from tabulate import tabulate

def find_duplicate_hostnames(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    hostnames = collections.defaultdict(int)
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2:
            hostnames[parts[1]] += 1

    duplicates = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 3 and hostnames[parts[1]] > 1:
            duplicates.append([parts[1], parts[0], parts[2]])

    duplicates.sort(key=lambda x: (x[0], x[1], x[2]))

    headers = ["Hostname", "IP4 Address", "MAC Address"]
    print(tabulate(duplicates, headers=headers, tablefmt="plain"))

    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "tabulate", "-y", "-q"])

if __name__ == '__main__':
    find_duplicate_hostnames('/users/jimgiordan/kh.txt')
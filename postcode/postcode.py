#!/usr/bin/env python3
# prompt: get my postcode based on my ip address

import subprocess
import sys
import json

try:
  import requests
except ImportError:
  subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
  import requests

def get_postcode_from_ip():
  try:
    response = requests.get('https://ipinfo.io/json')
    response.raise_for_status()  # Raise an exception for bad status codes

    data = response.json()
    if 'postal' in data:
      return data['postal']
    elif 'loc' in data:
      # If postcode is not available, try using location to get more info (less reliable)
      location = data['loc']
      # You would need to use a geocoding service here to get the postcode from latitude/longitude
      print("Postcode not directly available. Location:", location)
      # Example using a geocoding service (you'll need an API key) - replace with your actual service
      # geocode_response = requests.get(f"https://api.examplegeocode.com/?lat={location.split(',')[0]}&lon={location.split(',')[1]}&key=YOUR_API_KEY")
      # ...process geocode_response...
      return None # Or return the geocoding result if successful

    else:
      return None # Or handle this case appropriately
      
  except requests.exceptions.RequestException as e:
    print(f"Error fetching IP information: {e}")
    return None

postcode = get_postcode_from_ip()

if postcode:
  print("Your postcode:", postcode)
else:
  print("Could not determine your postcode.")

subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "requests", "-y", "-q"])
#!/usr/bin/env python3
import subprocess, sys

try:
  from skyfield import api, almanac
except ImportError:
  #print("Info: 'skyfield' module not found. Installing...")
  subprocess.check_call([sys.executable, "-m", "pip", "install", "skyfield", "-q"])
  from skyfield import api, almanac

try:
  from colorama import Fore, Back, Style, init
except ImportError:
  subprocess.check_call(sys.executable, "m", "pip", "install", "colorama", "-q")
  from colorama import Fore, Back, Style, init

# Load the ephemeris (data about celestial objects)
load = api.Loader('/tmp') # create a Loader object
planets = load('de421.bsp') # Use the Loader object to load the ephemeris

# Convert today's date to a Skyfield Time object
ts = api.load.timescale()
t = ts.now()

# Calculate the moon's phase (your existing logic)
astrometric = planets['earth'].at(t).observe(planets['earth'])
apparent = astrometric.apparent()

# Calculate the elongation using separation_from()
elongation = apparent.separation_from(planets['moon'].at(t))
elongation_degrees = elongation.degrees

# Calculate the phase angle, providing the sun's position
phase_angle = apparent.phase_angle(planets['sun']).degrees # Pass the sun object to phase_angle()

# Determine the moon phase name (your existing logic)
if phase_angle < 45:
  moon_phase = "New Moon"
elif phase_angle < 90:
  moon_phase = "Waxing Crescent"
elif phase_angle < 135:
  moon_phase = "First Quarter"
elif phase_angle < 180:
  moon_phase = "Waxing Gibbous"
elif phase_angle < 225:
  moon_phase = "Full Moon"
elif phase_angle < 270:
  moon_phase = "Waning Gibbous"
elif phase_angle < 315:
  moon_phase = "Last Quarter"
else:
  moon_phase = "Waning Crescent"



# --- Enhance with skyfield.almanac for Season ---
season_function = almanac.seasons(planets)
current_season_index = season_function(t)
season_names = ['Spring', 'Summer', 'Autumn', 'Winter']
current_season = season_names[current_season_index]



# --- Enhance with skyfield.almanac for Moon Phases ---
moon_phase_function = almanac.moon_phases(planets)
current_moon_phase_index = moon_phase_function(t)
moon_node_function = almanac.moon_nodes(planets)
current_moon_node_index = int(not moon_node_function(t))
current_moon_node = almanac.MOON_NODES[current_moon_node_index]
current_moon_phase_almanac = almanac.MOON_PHASES[current_moon_phase_index]

# Print the result
print(f"It is currently {Fore.MAGENTA}{current_season}{Style.RESET_ALL} and we have an {Fore.GREEN}{current_moon_node} {current_moon_phase_almanac}{Style.RESET_ALL} or a {Fore.CYAN}{moon_phase}{Style.RESET_ALL}")
'''
print(f"Today's moon phase (from phase angle): {moon_phase}")
print(f"Current Season: {current_season}")
print(f"It is currently [38;5;165m{current_season}[0m and we have an [38;5;46m{current_moon_node} {current_moon_phase_almanac}[0m or a [38;5;51m{moon_phase}[0m")
'''

subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "skyfield", "colorama", "-y", "-q"])
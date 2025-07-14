#!/usr/bin/env python3
import subprocess, sys
from datetime import datetime, timezone

try:
    from skyfield import api, almanac
except ImportError:
    #print("Info: 'skyfield' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "skyfield", "-q"])
    from skyfield import api, almanac

# Load the ephemeris (data about celestial objects)
load = api.Loader('/tmp') # Correctly create a Loader object
planets = load('de421.bsp') # Use the Loader object to load the ephemeris

earth = planets['earth']
moon = planets['moon']
sun = planets['sun']

# Convert today's date to a Skyfield Time object
ts = api.load.timescale()
t = ts.now()

# Calculate the moon's phase (your existing logic)
astrometric = earth.at(t).observe(planets['earth'])
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

# Print the result
print(f"Today's moon phase (from phase angle): {moon_phase}")

# --- Enhance with skyfield.almanac for Season ---
season_function = almanac.seasons(planets)
current_season_index = season_function(t)
season_names = ['Spring', 'Summer', 'Autumn', 'Winter']
current_season = season_names[current_season_index]
print(f"Current Season: {current_season}")


# --- Enhance with skyfield.almanac for Moon Phases ---
moon_phase_function = almanac.moon_phases(planets)
current_moon_phase_index = moon_phase_function(t)
current_moon_phase_almanac = almanac.MOON_PHASES[current_moon_phase_index]
print(f"Current Moon Phase (from almanac): {current_moon_phase_almanac}")

# --- Enhance with skyfield.almanac for Moon Nodes ---
moon_node_function = almanac.moon_nodes(planets)
current_moon_node_index = int(not moon_node_function(t))
current_moon_node = almanac.MOON_NODES[current_moon_node_index]
print(f"Current Moon Node: {current_moon_node}")


subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "skyfield", "-y", "-q"])
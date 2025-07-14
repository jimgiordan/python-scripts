#!/usr/bin/env python3
import subprocess, sys

try:
    from skyfield import api, almanac
except ImportError:
    #print("Info: 'skyfield' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "skyfield", "-q"])
    from skyfield import api, almanac

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
print(f"It is currently \033[35m{current_season}\033[0m and we have an \033[92m{current_moon_node} {current_moon_phase_almanac}\033[0m or a \033[36m{moon_phase}\033[0m")
'''
print(f"Today's moon phase (from phase angle): {moon_phase}")
print(f"Current Season: {current_season}")
print(f"It is currently [38;5;165m{current_season}[0m and we have an [38;5;46m{current_moon_node} {current_moon_phase_almanac}[0m or a [38;5;51m{moon_phase}[0m")
'''

subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "skyfield", "-y", "-q"])
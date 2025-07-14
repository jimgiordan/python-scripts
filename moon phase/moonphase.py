#!/usr/bin/env python3
import subprocess, sys

try:
  from skyfield import api, almanac
except ImportError:
  subprocess.check_call([sys.executable, "-m", "pip", "install", "skyfield", "-q"])
  from skyfield import api, almanac

try:
  from colorama import Fore, Back, Style, init
except ImportError:
  subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama", "-q"])
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

moon_phase_names = [
  "New Moon",
  "Waxing Crescent",
  "First Quarter",
  "Waxing Gibbous",
  "Full Moon",
  "Waning Gibbous",
  "Last Quarter",
  "Waning Crescent"
]
index = int((phase_angle % 360) // 45)
moon_phase = moon_phase_names[index]

season_function = almanac.seasons(planets)
current_season_index = season_function(t)
season_names = [
  "Spring", 
  "Summer", 
  "Autumn", 
  "Winter"
]
current_season = season_names[current_season_index]

moon_phase_function = almanac.moon_phases(planets)
current_moon_phase_index = moon_phase_function(t)
moon_node_function = almanac.moon_nodes(planets)
current_moon_node_index = int(not moon_node_function(t))
current_moon_node = almanac.MOON_NODES[current_moon_node_index]
current_moon_phase_almanac = almanac.MOON_PHASES[current_moon_phase_index]

data = {
  "phase": f"{Fore.CYAN}{moon_phase}{Style.RESET_ALL}", 
  "season": f"{Fore.MAGENTA}{current_season}{Style.RESET_ALL}",
  "almanac": f"{Fore.GREEN}{current_moon_phase_almanac} {current_moon_node}{Style.RESET_ALL}"
}

print(
  f"It is currently " 
  f"{data['season']} and we have a " 
  f"{data['almanac']} or a " 
  f"{data['phase']}" 
  )

subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "skyfield", "colorama", "-y", "-q"])
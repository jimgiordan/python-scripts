#!/usr/bin/env python3
import subprocess, sys
from datetime import datetime, timezone

try:
    from skyfield.api import load, Topos, Loader
except ImportError:
    #print("Info: 'skyfield' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "skyfield", "-q"])
    from skyfield.api import load, Topos, Loader

# Get today's date
today = datetime.now(timezone.utc)

# Load the ephemeris (data about celestial objects)
load = Loader('/tmp')
planets = load('de421.bsp')

# Define the location (Earth)
earth = planets['earth']

# Define the moon
moon = planets['moon']

# Define the sun
sun = planets['sun'] # Define the sun object

# Convert today's date to a Skyfield Time object
ts = load.timescale()
t = ts.from_datetime(today)

# Calculate the moon's phase
astrometric = earth.at(t).observe(moon)
apparent = astrometric.apparent()

# Calculate the elongation using separation_from()
elongation = apparent.separation_from(earth.at(t))
elongation_degrees = elongation.degrees

# Calculate the phase angle, providing the sun's position
phase_angle = apparent.phase_angle(sun).degrees # Pass the sun object to phase_angle()

# Determine the moon phase name
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
print(f"Today's moon phase: {moon_phase}")

subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "skyfield", "-y", "-q"])

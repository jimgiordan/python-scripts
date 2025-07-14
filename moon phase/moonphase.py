#!/usr/bin/env python3
import subprocess, sys

try:
    from skyfield import api
except ImportError:
    #print("Info: 'skyfield' module not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "skyfield", "-q"])
    from skyfield import api

# Load the ephemeris (data about celestial objects)
load = api.Loader('/tmp')
planets = api.load('de421.bsp')

earth = planets['earth']
moon = planets['moon']
sun = planets['sun']

# Convert today's date to a Skyfield Time object
ts = api.load.timescale()
t = ts.now()

# Calculate the moon's phase
astrometric = earth.at(t).observe(planets['earth'])
apparent = astrometric.apparent()

# Calculate the elongation using separation_from()
elongation = apparent.separation_from(planets['moon'].at(t))
elongation_degrees = elongation.degrees

# Calculate the phase angle, providing the sun's position
phase_angle = apparent.phase_angle(planets['sun']).degrees # Pass the sun object to phase_angle()

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

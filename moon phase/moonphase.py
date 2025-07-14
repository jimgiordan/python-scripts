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
loader = api.Loader('/tmp') # Correctly create a Loader object
planets = loader.load('de421.bsp') # Use the Loader object to load the ephemeris

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
# Define a time range for the current year
t_start_year = ts.utc(t.utc_datetime().year, 1, 1)
t_end_year = ts.utc(t.utc_datetime().year + 1, 1, 1)

# Get season events
times_seasons, events_seasons = almanac.seasons(ts, earth)

# Find the season that just passed or is current
# Filter events that have already occurred
past_season_indices = (times_seasons <= t).nonzero()[0]
if past_season_indices.size > 0:
    current_season_index = past_season_indices[-1]
    season_names = ['Spring', 'Summer', 'Autumn', 'Winter']
    current_season = season_names[events_seasons[current_season_index]]
    print(f"Current Season: {current_season}")
else:
    print("Could not determine current season (no past season events found this year).")


# --- Enhance with skyfield.almanac for Moon Phases ---
# Define a time range around the current time (e.g., +/- 2 days)
t_moon_start = ts.utc(t.utc_datetime().year, t.utc_datetime().month, t.utc_datetime().day - 2)
t_moon_end = ts.utc(t.utc_datetime().year, t.utc_datetime().month, t.utc_datetime().day + 2)

# Get moon phase events
times_moon_phases, events_moon_phases = almanac.moon_phases(planets)(t_moon_start, t_moon_end)

# Find the most recent moon phase event
past_moon_phase_indices = (times_moon_phases <= t).nonzero()[0]
if past_moon_phase_indices.size > 0:
    closest_phase_index = past_moon_phase_indices[-1]
    phase_names_almanac = ['New Moon', 'First Quarter', 'Full Moon', 'Last Quarter']
    current_moon_phase_almanac = phase_names_almanac[events_moon_phases[closest_phase_index]]
    print(f"Current Moon Phase (from almanac): {current_moon_phase_almanac}")
else:
    print("Could not determine current moon phase from almanac (no recent events found).")


subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "skyfield", "-y", "-q"])
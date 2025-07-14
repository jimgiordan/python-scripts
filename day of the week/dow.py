#!/usr/bin/env python3

def day_of_week(date_str):
    """
    Calculates the day of the week and formats the output with month name.

    Args:
        date_str: The date string in either "dd/mm/yyyy" or "dd-mm-yyyy" format.

    Returns:
        A formatted string with the day of the week, month name, day off indication, or an error message.
    """

    # define a list of weekday names and month names
    days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

    try:
        # split the date string using either '/' or '-' as the delimiter
        day, month, year = map(int, date_str.replace('/', '-').split('-'))

        mname = months[month - 1]

        # date validation
        if year < 1:
            raise ValueError("Sorry only AD dates can be handled")
        if not (1 <= month <= 12):
            raise ValueError("Invalid month.")
        else:
            if month in [4,6,9,11]:
                if day > 30:
                    raise ValueError("Invalid date.")
            else:
                if month == 2:
                    if day > 29:
                        raise ValueError("Invalid date.")
                else:
                    if day > 31:
                        raise ValueError("Invalid date.")

        # leap year validation
        if month == 2 and day == 29 and not (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)):
            raise ValueError("Invalid date: Not a leap year.")

        # Zellercongruence calculation
        if month < 3:
          m = month + 12
          y = year - 1
        else:
          m = month
          y = year

        c = y // 100
        y = y % 100
        day_of_week_num = (c // 4 - 2 * c + y + y // 4 + 13 * (m + 1) // 5 + day - 1) % 7

        # format the output string
        return f"The day of the week for {day} of {mname} {year} is {days[(day_of_week_num + 7) % 7]}"

    except ValueError as e:
        return f"Error: {e}"

# get input from the user
result = "Error"
attempts = 0
while "Error" in result:
  if attempts < 3:
    attempts += 1
    date_str = input("Enter the date (dd/mm/yyyy or dd-mm-yyyy): ")
    result = day_of_week(date_str)
    print(result)
  else:
    print("Too many attempts. Exiting program.")
    break

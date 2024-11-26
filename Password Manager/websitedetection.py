from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

# Set up the Chrome driver
driver = webdriver.Chrome()

# Open a website
driver.get("https://www.google.com")

# Wait for the page to load
time.sleep(2)

# Get the current URL of the active tab
current_url = driver.current_url
print("Active tab URL:", current_url)

# Keep the browser open indefinitely
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Exiting...")

# Close the browser when the script is interrupted
driver.quit()

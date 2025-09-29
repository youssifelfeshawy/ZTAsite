#!/bin/bash

# Master script: ping -> SFTP -> website, repeat every 3 minutes
# All in one file, using heredocs for Expect and Python

# Unified log file
LOG="user_simulation_log.txt"

while true; do
  echo "Starting simulation cycle at $(date)" >> $LOG
  echo "-------------------------------------" >> $LOG

  # Ping section
  echo "=== Ping Tests ===" >> $LOG
  # Test ping to Gateway (should succeed)
  echo "Pinging Gateway (192.168.1.1)..." >> $LOG
  ping -c 4 192.168.1.1 >> $LOG 2>&1
  if [ $? -eq 0 ]; then
      echo "Gateway ping: SUCCESS" >> $LOG
  else
      echo "Gateway ping: FAIL" >> $LOG
  fi
  # Test ping to Main Server (should succeed via gateway)
  echo "Pinging Main Server (192.168.1.130)..." >> $LOG
  ping -c 4 192.168.1.130 >> $LOG 2>&1
  if [ $? -eq 0 ]; then
      echo "Main Server ping: SUCCESS" >> $LOG
  else
      echo "Main Server ping: FAIL" >> $LOG
  fi
  # Test ping to Auth Server (should succeed via gateway)
  echo "Pinging Auth Server (192.168.1.134)..." >> $LOG
  ping -c 4 192.168.1.134 >> $LOG 2>&1
  if [ $? -eq 0 ]; then
      echo "Auth Server ping: SUCCESS" >> $LOG
  else
      echo "Auth Server ping: FAIL" >> $LOG
  fi
  # Test external internet (should succeed via gateway NAT)
  echo "Pinging external (google.com)..." >> $LOG
  ping -c 4 google.com >> $LOG 2>&1
  if [ $? -eq 0 ]; then
      echo "External ping: SUCCESS" >> $LOG
  else
      echo "External ping: FAIL" >> $LOG
  fi

  # SFTP section (using Expect heredoc)
  echo "=== SFTP Test ===" >> $LOG
  expect <<EOF >> $LOG 2>&1
set timeout 10
set host "192.168.1.130"
set user "user1"
# Assumes key-based auth is set up; no password needed. If password, add: set password "yourpass"
set temp_dir "/tmp"
set file_to_download "files/data1.text"
set local_path "\$temp_dir/data1.text"

spawn sftp \$user@\$host
expect "sftp> "

# List files (optional)
send "ls\r"
expect "sftp> "

# Download the sample file
send "get \$file_to_download \$local_path\r"
expect "sftp> "

# Exit
send "exit\r"
expect eof

# Verify download
if {[file exists \$local_path]} {
    puts "SFTP download SUCCESS at [clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S}]"
    # Delete the file to save storage
    file delete \$local_path
} else {
    puts "SFTP download FAIL at [clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S}]"
}
EOF

  # Website section (using Python heredoc)
  echo "=== Website Test ===" >> $LOG
  python3 <<EOF >> $LOG 2>&1
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service
import time
import logging

# Setup logging (appends to the same file as master)
logging.basicConfig(filename='user_simulation_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s', filemode='a')

# Config: Adjust URLs, credentials
SITE_URL = "http://192.168.1.130/ZTAsite/index.php"
KEYCLOAK_LOGIN_URL = "http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/auth" # Approximate; check redirect
USERNAME = "user1" # or "user2"
PASSWORD = "user1" # Adjust

# Specify GeckoDriver path
service = Service(executable_path='/usr/local/bin/geckodriver')

try:
    # Start Firefox driver (headless for background run)
    options = webdriver.FirefoxOptions()
    options.add_argument("--headless")
    driver = webdriver.Firefox(service=service, options=options)
    driver.get(SITE_URL)

    # Wait for redirect to Keycloak login
    wait = WebDriverWait(driver, 10)
    username_field = wait.until(EC.presence_of_element_located((By.ID, "username"))) # Keycloak login field ID
    password_field = driver.find_element(By.ID, "password")
    
    # Simulate user typing credentials
    username_field.send_keys(USERNAME)
    time.sleep(1) # Simulate typing delay
    password_field.send_keys(PASSWORD)
    time.sleep(1)
    
    # Submit login
    login_button = driver.find_element(By.ID, "kc-login") # Keycloak submit button ID
    login_button.click()
    
    # Wait for redirect back to site and check if logged in (look for success element, e.g., a welcome message)
    wait.until(EC.url_contains("/ZTAsite")) # Adjust based on post-login URL
    if "Stage 1" in driver.page_source: # Adjusted to match site content after login (from image: "Stage 1: Build the Virtual Machines")
        print("Login SUCCESS. Site accessed.")
    else:
        print("Login FAIL.")
    
    # Simulate browsing: e.g., click a link or download if applicable
    # Example: If there's a download button, find and click it
    # download_button = driver.find_element(By.ID, "download-btn")
    # download_button.click()
    
except Exception as e:
    print(f"Error during test: {str(e)}")

finally:
    if 'driver' in locals():
        driver.quit()
EOF

  echo "Cycle complete." >> $LOG
  echo "" >> $LOG  # Empty line for separation

  # Wait 3 minutes (180 seconds)
  sleep 180
done

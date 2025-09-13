#!/bin/bash

while true; do
  # Log file - append with timestamp for each run
  LOG="connectivity_log.txt"
  echo "Starting connectivity tests at $(date)" >> $LOG
  echo "-------------------------------------" >> $LOG

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

  echo "Tests complete for this cycle." >> $LOG
  echo "" >> $LOG  # Empty line for separation

  # Wait 10 minutes (600 seconds)
  sleep 600
done
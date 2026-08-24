#!/bin/bash
# Activitate benignă tipică de server — declanșează aceleași reguli ca atacurile
while true; do
  sudo chmod 644 /tmp/backup_$(date +%s).log 2>/dev/null
  tar czf /tmp/backup_$(date +%s).tar.gz /var/log/*.log 2>/dev/null
  sudo useradd -M -s /usr/sbin/nologin svc_$(date +%s) 2>/dev/null
  curl -s https://api.github.com/zen > /dev/null
  history -c
  sleep 120
done

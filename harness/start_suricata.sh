#!/bin/bash
# Senzor Suricata pentru ramura web.
# Bridge-ul Docker se schimba la recrearea retelei - verifica-l cu:
#   ip -brief addr | grep br-
BRIDGE="br-4b546cd1525f"
sudo kill -9 $(pgrep suricata) 2>/dev/null; sleep 2
sudo rm -f /var/run/suricata.pid
mkdir -p /tmp/suri
sudo suricata -i "$BRIDGE" -l /tmp/suri \
  -S /var/lib/suricata/rules/web-only.rules \
  --set vars.address-groups.HOME_NET="any" \
  --set vars.address-groups.EXTERNAL_NET="any" -D
echo "Astept pornirea..."
for i in $(seq 1 20); do
  grep -q "Engine started" /tmp/suri/suricata.log 2>/dev/null && echo "GATA" && exit 0
  sleep 5
done
echo "TIMEOUT - verifica /tmp/suri/suricata.log"

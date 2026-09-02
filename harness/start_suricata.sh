#!/bin/bash
# Porneste senzorul Suricata pentru ramura web.
#
# Deduce singur bridge-ul Docker si IP-ul containerului, pentru ca amandoua
# se schimba cand reteaua e recreata. Configuratia de retea e cea gasita
# empiric pe 2026-08-31:
#
#   - interfata: bridge-ul retelei aplicatiei, NU lo si NU enp0s8.
#     Traficul catre localhost:8091 e transferat de docker-proxy in container
#     prin bridge; pe lo se vede doar handshake-ul IPv6, fara payload.
#   - HOME_NET si HTTP_SERVERS: DOAR containerul. Pus pe "any", EXTERNAL_NET
#     devine "!any" adica vid, si regulile directionale
#     EXTERNAL_NET -> HTTP_SERVERS nu se aprind niciodata.
#   - logurile in /var/log/suricata, nu /tmp, care se goleste la reboot.

set -u

CONTAINER="sample_repo-web-1"
NETWORK="sample_repo_default"
LOGDIR="/var/log/suricata"
RULES="/var/lib/suricata/rules/web-only.rules"

# --- deduce IP-ul containerului -------------------------------------------
SERVER_IP=$(docker inspect "$CONTAINER" \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)

if [ -z "$SERVER_IP" ]; then
  echo "EROARE: containerul $CONTAINER nu ruleaza."
  echo "  cd ~/soc-lab/sample_repo && docker compose up -d"
  exit 1
fi

# --- deduce bridge-ul ------------------------------------------------------
NET_ID=$(docker network inspect "$NETWORK" --format '{{.Id}}' 2>/dev/null)
if [ -z "$NET_ID" ]; then
  echo "EROARE: reteaua $NETWORK nu exista."
  exit 1
fi
BRIDGE="br-${NET_ID:0:12}"

if ! ip link show "$BRIDGE" > /dev/null 2>&1; then
  echo "EROARE: interfata $BRIDGE nu exista. Interfete disponibile:"
  ip -brief addr | grep br-
  exit 1
fi

echo "[i] container : $CONTAINER ($SERVER_IP)"
echo "[i] bridge    : $BRIDGE"
echo "[i] loguri    : $LOGDIR"

# --- curata instantele vechi ----------------------------------------------
# pkill si killall nu prind mereu procesul; PID-urile explicite, da.
PIDS=$(ps aux | grep "[s]uricata -i" | awk '{print $2}')
if [ -n "$PIDS" ]; then
  echo "[i] opresc instantele vechi: $PIDS"
  sudo kill -9 $PIDS 2>/dev/null
  sleep 3
fi
sudo rm -f /var/run/suricata.pid
sudo mkdir -p "$LOGDIR"
sudo rm -f "$LOGDIR/eve.json" "$LOGDIR/suricata.log"

# --- porneste --------------------------------------------------------------
sudo suricata -i "$BRIDGE" -l "$LOGDIR" \
  -S "$RULES" \
  --set vars.address-groups.HOME_NET="[$SERVER_IP/32]" \
  --set vars.address-groups.EXTERNAL_NET="any" \
  --set vars.address-groups.HTTP_SERVERS="[$SERVER_IP/32]" \
  -D

# --- asteapta pornirea efectiva -------------------------------------------
# Cu ~8000 de reguli dureaza intre 30 si 90 de secunde. Pana la
# "Engine started", orice cerere trimisa e ignorata.
echo -n "[i] astept pornirea motorului"
for i in $(seq 1 24); do
  if grep -q "Engine started" "$LOGDIR/suricata.log" 2>/dev/null; then
    echo " GATA"
    # agentul Elastic trebuie sa poata citi fisierul
    sudo chmod 755 "$LOGDIR"
    sudo chmod 644 "$LOGDIR/eve.json"
    echo "[i] o singura instanta: $(ps aux | grep -c '[s]uricata -i')"
    exit 0
  fi
  echo -n "."
  sleep 5
done

echo " TIMEOUT"
echo "Verifica: tail -20 $LOGDIR/suricata.log"
exit 1

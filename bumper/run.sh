#!/bin/sh
# Start Bumper; if a map robot is configured, also keep its map, position and cleaned path drawn for HA.
ANNOUNCE_IP=$(/bumper/.venv/bin/python -c 'import json;print(json.load(open("/data/options.json")).get("announce_ip",""))' 2>/dev/null)
if [ -n "$ANNOUNCE_IP" ]; then
  export BUMPER_ANNOUNCE_IP="$ANNOUNCE_IP"
fi
BOT=$(/bumper/.venv/bin/python -c 'import json;print(json.load(open("/data/options.json")).get("map_bot",""))' 2>/dev/null)
if [ -n "$BOT" ]; then
  (sleep 60; exec /bumper/.venv/bin/python /deebot_map.py --bot "$BOT" --out /share/deebot/mappa.png) &
fi
/bumper/.venv/bin/python /repair_db.py "$DB_FILE"
exec /bumper/.venv/bin/bumper

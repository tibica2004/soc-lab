import json, base64, urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from normalize import load_alerts

ES = "http://192.168.56.10:9200"
AUTH = base64.b64encode(b"elastic:changeme123").decode()

def search(index, body):
    req = urllib.request.Request(f"{ES}/{index}/_search?size=3",
                                 data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Basic {AUTH}")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)["hits"]["hits"]

alerts = load_alerts(Path("../groundtruth/alerts_raw_v2.json"))
missing = [a for a in alerts if not a.process_command_line]
print(f"{len(missing)} alerte fara linie de comanda\n")

for alert in missing[:5]:
    ts = datetime.fromisoformat(alert.timestamp)
    body = {"query": {"bool": {"filter": [
        {"term": {"host.name": alert.host_name}},
        {"range": {"@timestamp": {
            "gte": (ts - timedelta(seconds=30)).isoformat(),
            "lte": (ts + timedelta(seconds=30)).isoformat()}}}]}}}
    try:
        hits = search("logs-endpoint.events.process-*", body)
    except Exception as e:
        print(f"  eroare: {e}"); continue
    print(f"--- {alert.rule_name}  ({alert.timestamp})")
    if not hits:
        print("    niciun eveniment de proces in fereastra\n")
    for h in hits:
        src = h["_source"]
        print("    ", src.get("process", {}).get("command_line", "<fara cmdline>"))
    print()

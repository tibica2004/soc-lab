from pathlib import Path

from ablation import load_ground_truth, label_alerts
from extract import build_alert_body
from normalize import load_alerts

alerts = load_alerts(Path("../groundtruth/alerts_raw.json"))
windows = load_ground_truth(Path("../groundtruth/runs.csv"))

for alert, label in label_alerts(alerts, windows)[:10]:
    print(f"--- {label}  {alert.rule_name}")
    print(build_alert_body(alert))
    print()

import dataclasses
from collections import Counter
from pathlib import Path

from ablation import load_ground_truth, label_alerts
from extract import Extractor
from features import FEATURE_FIELDS
from normalize import load_alerts

BLANK = dict(reason=None, host_name=None, user_name=None, process_name=None,
             process_command_line=None, process_parent_name=None,
             rule_name=None, event_category=[], event_type=[])

alerts = load_alerts(Path("../groundtruth/alerts_raw.json"))
pairs = label_alerts(alerts, load_ground_truth(Path("../groundtruth/runs.csv")))[:10]
ex = Extractor()

for name, mutate in (("REAL", lambda a: a), ("GOL", lambda a: dataclasses.replace(a, **BLANK))):
    dist = {f: Counter() for f in FEATURE_FIELDS}
    for alert, _ in pairs:
        r = ex.extract(mutate(alert))
        if r.ok:
            for f in FEATURE_FIELDS:
                dist[f][getattr(r.features, f).value] += 1
    print(f"=== {name}")
    for f in FEATURE_FIELDS:
        print(f"  {f}: {dict(dist[f])}")

import os
import glob
import csv

sigma_dir = "/home/besleaga/proiect/soc-lab/sample_repo"
output_csv = "/home/besleaga/proiect/soc-lab/groundtruth/github_runs.csv"

print("[*] Citesc regulile Sigma din repository-ul extern (mod nativ)...")

rows = []
yaml_files = glob.glob(os.path.join(sigma_dir, "**", "*.yml"), recursive=True)
linux_files = [f for f in yaml_files if "linux" in f.lower()][:15] # Luam 15 reguli

for filepath in linux_files:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Extragem titlul simplu cautand linia 'title:'
            title = "Linux Security Rule"
            description = "No description."
            mitre_id = "T1000"
            
            for line in content.splitlines():
                if line.startswith("title:"):
                    title = line.replace("title:", "").strip().strip('"').strip("'")
                elif line.startswith("description:"):
                    description = line.replace("description:", "").strip().strip('"').strip("'")
                elif "attack.t" in line.lower():
                    # Gasim ceva de genul attack.t1059
                    parts = line.strip().split('.')
                    for p in parts:
                        if p.startswith('t') and p[1:].isdigit():
                            mitre_id = "T" + p[1:].upper()
            
            rows.append({
                "timestamp_utc": "2026-08-28T12:00:00+03:00",
                "technique_id": mitre_id,
                "test_number": 1,
                "host": "github-node-01",
                "label": "TP",
                "expected_rules": title,
                "notes": description
            })
    except Exception as e:
        pass

# Scriem in formatul CSV
with open(output_csv, mode='w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp_utc", "technique_id", "test_number", "host", "label", "expected_rules", "notes"])
    writer.writeheader()
    writer.writerows(rows)

print(f"[+] S-a generat cu succes fisierul cu {len(rows)} alerte din GitHub: {output_csv}")

import csv
import os
from test_triage import extract_features_with_antares, decide_alert_verdict

def run_benchmark(csv_path: str):
    print(f"\n[🚀] Incepem evaluarea in masa a fisierului: {csv_path}")
    
    metrics = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    
    with open(csv_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            raw_alert_text = (
                f"Technique: {row['technique_id']} | "
                f"Rule triggered: {row['expected_rules']} | "
                f"Host: {row['host']} | "
                f"Notes: {row['notes']}"
            )
            
            ground_truth = row['label'].strip().upper()
            
            print(f"\n[-] Analizez alerta: {row['expected_rules']}")
            print(f"    Adevar (CSV): {ground_truth}")
            
            features = extract_features_with_antares(raw_alert_text)
            if not features:
                print("    [!] Extragerea a eșuat (schema invalida). Sarim peste...")
                continue
            
            verdict = decide_alert_verdict(features, risk_score=600)
            print(f"    Verdict Arbore: {verdict}")
            
            is_actionable = (verdict == "Actionable")
            is_true_attack = (ground_truth == "TP")
            
            if is_true_attack and is_actionable:
                metrics["TP"] += 1
                print("    [+] Corect: Atac detectat (TP)")
            elif is_true_attack and not is_actionable:
                metrics["FN"] += 1
                print("    [-] Gresit: Atac ratat (FN)")
                print(f"    [DEBUG] Fapte extrase: {features.model_dump()}")
            elif not is_true_attack and not is_actionable:
                metrics["TN"] += 1
                print("    [+] Corect: Alarma falsa ignorata cu succes (TN) - ABTINERE FUNCTIONALA!")
            elif not is_true_attack and is_actionable:
                metrics["FP"] += 1
                print("    [-] Gresit: Alarma falsa escaladata degeaba (FP)")

    total = sum(metrics.values())
    
    report = f"""
=========================================================
RAPORT FINAL BENCHMARK (EXTRACT-THEN-DECIDE)
=========================================================
Total alerte procesate: {total}

-- Matricea de Confuzie --
Adevarat Pozitive (TP - Atac corect oprit)        : {metrics['TP']}
Fals Negative     (FN - Atac ratat)               : {metrics['FN']}
Adevarat Negative (TN - Alarma falsa ignorata)    : {metrics['TN']}
Fals Pozitive     (FP - Alarma falsa escaladata)  : {metrics['FP']}

-- Metrici de Performanta --
"""
    tpr = metrics['TP'] / (metrics['TP'] + metrics['FN']) if (metrics['TP'] + metrics['FN']) > 0 else 0
    fpr = metrics['FP'] / (metrics['FP'] + metrics['TN']) if (metrics['FP'] + metrics['TN']) > 0 else 0
    
    report += f"True Positive Rate (Detectie): {tpr*100:.2f}%\n"
    report += f"False Positive Rate (Zgomot):  {fpr*100:.2f}%\n"
    report += "=========================================================\n"
    
    print(report)
    
    results_dir = "/home/besleaga/proiect/soc-lab/results/"
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, "2026-08-27-extract-then-decide-benchmark.md"), "w") as f:
        f.write(report)
        print(f"[i] Raportul a fost salvat in: {os.path.join(results_dir, '2026-08-27-extract-then-decide-benchmark.md')}")

if __name__ == "__main__":
    import sys
    # Daca ii dam un argument in terminal, il foloseste pe ala. Daca nu, il ia pe cel default.
    if len(sys.argv) > 1:
        csv_file_path = sys.argv[1]
    else:
        csv_file_path = "/home/besleaga/proiect/soc-lab/groundtruth/runs.csv"
        
    run_benchmark(csv_file_path)

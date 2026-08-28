import sys
import json
from pathlib import Path
from llama_cpp import Llama

from normalize import load_alerts
from extract import Extractor
from decide import decide, Verdict, all_rule_ids

MODEL_PATH = "/home/tiberiu/antares-1b-q8_0.gguf"

def init_antares():
    print("[*] Incarc Antares 1B in memorie pentru inspectie de cod (Deep Analysis)...")
    return Llama(
        model_path=MODEL_PATH,
        n_ctx=2048,
        verbose=False,
        temperature=0.1
    )

def analyze_payload_with_ai(llm, command_line: str) -> str:
    prompt = f"""You are an expert SOC L2 Analyst and Malware Reverse Engineer.
Analyze the following command line or script executed on a Linux endpoint.
Explain concisely what it does, what tools it uses (e.g., Atomic Red Team, base64, nc), and if it is malicious.

Command: {command_line}

Analysis:"""

    response = llm(
        prompt,
        max_tokens=150,
        stop=["\n\n", "User:"],
        echo=False
    )
    
    return response["choices"][0]["text"].strip()

def run_hybrid_soc():
    alerts_path = Path("../groundtruth/alerts_raw.json")
    if not alerts_path.exists():
        print(f"[!] Fisierul nu exista: {alerts_path}")
        return

    alerts = load_alerts(alerts_path)
    extractor = Extractor() 
    llm = None 

    print(f"[*] Am incarcat {len(alerts)} alerte. Incep triajul hibrid...")
    print("=" * 60)

    actionable_count = 0
    benign_count = 0

    for i, alert in enumerate(alerts): # Rulam pe primele 20 de proba
        ext_result = extractor.extract(alert)
        if not ext_result.ok:
            continue

        # AICI AM CORECTAT: Am adaugat 'alert' ca al doilea parametru
        decision = decide(ext_result.features, alert, all_rule_ids()) 

        if decision.verdict == Verdict.ACTIONABLE:
            actionable_count += 1
            print(f"\n[🚨 ACTIONABLE] Regula: {alert.rule_name}")
            
            if alert.process_command_line:
                print(f"    [+] Payload detectat: {alert.process_command_line}")
                print("    [*] Trimit catre Antares 1B pentru analiza...")
                
                if llm is None:
                    llm = init_antares()
                
                ai_analysis = analyze_payload_with_ai(llm, alert.process_command_line)
                print(f"    [🤖 ANTARES L2 INSIGHT]:\n    {ai_analysis}")
            else:
                print("    [-] Nu exista linie de comanda pentru inspectie AI.")
            print("-" * 60)
        else:
            benign_count += 1
            sys.stdout.write('.')
            sys.stdout.flush()

    print(f"\n\n[*] Triaj finalizat pentru primele 20 de alerte.")
    print(f"[*] Zgomot eliminat de Regex+Arbore: {benign_count}")
    print(f"[*] Alerte escalate si analizate de AI: {actionable_count}")

if __name__ == "__main__":
    run_hybrid_soc()

import json
from enum import Enum
from pydantic import BaseModel, Field
from llama_cpp import Llama

class TechniqueCategory(str, Enum):
    ATTACK_TECHNIQUE = "attack_technique"  
    BENIGN_NOISE = "benign_noise"          

class TargetResource(str, Enum):
    CRITICAL_SYSTEM_COMPONENT = "critical_system_component" 
    NOISE_SCRIPT = "noise_script"
    GENERAL_SYSTEM_RESOURCE = "general_system_resource" 

class ActionIntent(str, Enum):
    TAMPERING_OR_ACCESS = "tampering_or_unauthorized_access"
    BENIGN_LIFECYCLE_EVENT = "benign_lifecycle_event"       
    UNKNOWN_INTENT = "unknown_intent" 

class AlertFeatures(BaseModel):
    technique_category: TechniqueCategory = Field(
        description="If the alert mentions a MITRE ID (T1059, T1078, T1548) or malicious action, choose 'attack_technique'. If it explicitly says 'NOISE' or 'Legitimate', choose 'benign_noise'."
    )
    target_resource: TargetResource = Field(
        description="If the alert attacks shadow, cron, SUID, or passwords, choose 'critical_system_component'. If it's explicitly a 'noise script', choose 'noise_script'. Otherwise 'general_system_resource'."
    )
    action_intent: ActionIntent = Field(
        description="If it describes reverse shells, unauthorized access, or tampering, choose 'tampering_or_unauthorized_access'. If it's a legitimate admin task/noise, choose 'benign_lifecycle_event'. Otherwise 'unknown_intent'."
    )

print("[*] Incarc modelul Antares 1B in memorie...")
try:
    llm = Llama(
        model_path="/home/besleaga/antares-1b-Q5_K_M.gguf", 
        n_ctx=2048,
        verbose=False,
        n_gpu_layers=-1
    )
except Exception as e:
    print(f"[!] Eroare la incarcarea modelului: {e}")
    llm = None

def extract_features_with_antares(raw_alert_text: str) -> AlertFeatures:
    if not llm: return None
    schema_json = AlertFeatures.model_json_schema()
    messages = [
        {"role": "system", "content": "You are an expert SOC L1 feature extractor. You MUST respond ONLY with valid JSON."},
        {"role": "user", "content": f"Extract the required features for this alert:\n\n{raw_alert_text}"}
    ]
    try:
        response = llm.create_chat_completion(
            messages=messages, response_format={"type": "json_object", "schema": schema_json}, temperature=0.0
        )
        return AlertFeatures(**json.loads(response["choices"][0]["message"]["content"]))
    except Exception:
        return None

def decide_alert_verdict(features: AlertFeatures, risk_score: int = 0) -> str:
    if features is None: return "Undetermined"
    
    # 0. GUARDRAIL DETERMINIST DE SIGURANȚĂ (SUPREMAȚIA WHITELIST-ULUI)
    # Dacă modelul a marcat ca zgomot sau Intentul este benign
    if features.technique_category == TechniqueCategory.BENIGN_NOISE:
        return "Benign Positive"
    if features.action_intent == ActionIntent.BENIGN_LIFECYCLE_EVENT:
        return "Benign Positive"

    # 1. ESCALADARE (BLACKLIST) - Prinde Atacurile reale
    if features.technique_category == TechniqueCategory.ATTACK_TECHNIQUE and features.action_intent == ActionIntent.TAMPERING_OR_ACCESS:
        return "Actionable"
    
    # Condiție unică pentru componente critice
    if features.target_resource == TargetResource.CRITICAL_SYSTEM_COMPONENT and features.action_intent == ActionIntent.TAMPERING_OR_ACCESS:
        return "Actionable"

    return "Benign Positive" # Default sigur pentru orice altceva

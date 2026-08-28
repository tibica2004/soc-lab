"""
Extragerea de trasaturi -- singurul loc din sistem care atinge modelul.

Trei invariante:

1. Promptul se construieste EXCLUSIV din campuri care exista in productie.
   `technique_id`, `label` si `notes` sunt adnotarile noastre de ground
   truth. Daca ajung in prompt, modelul citeste cheia de raspuns si
   masuratoarea nu mai inseamna nimic. Vezi ALLOWED_FIELDS si
   test_no_leak.py.

2. Esecul de extragere nu dispare. `evaluate.py` facea `continue` la
   schema invalida, deci cazul iesea din numitor: un sistem care refuza
   sa raspunda la o cincime din alerte arata identic cu unul care
   raspunde la toate. Aici statusul se propaga pana in raport.

3. `llama_cpp` se importa lazy. decide.py, features.py si testele se pot
   rula fara sa incarci 1B in memorie.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Literal

from features import FEATURE_FIELDS, AlertFeatures, flat_json_schema
from normalize import NormalizedAlert

#: Configuratia modelului. Singurul loc de schimbat la trecerea pe Q8_0.
MODEL_PATH = "/home/tiberiu/antares-1b-q8_0.gguf"
N_CTX = 2048
TEMPERATURE = 0.0
MAX_TOKENS = 512

#: Campurile din NormalizedAlert care au voie sa ajunga in prompt.
#: Sunt cele disponibile la runtime dintr-o alerta Elastic reala.
ALLOWED_FIELDS: tuple[str, ...] = (
    "rule_name",
    "reason",
    "host_name",
    "user_name",
    "process_name",
    "process_command_line",
    "process_parent_name",
    "event_category",
    "event_type",
)

ExtractionStatus = Literal["ok", "schema_invalid", "model_error", "empty_output"]


@dataclass
class ExtractionResult:
    """Rezultatul unei extrageri, inclusiv cand esueaza."""

    alert_uuid: str
    features: AlertFeatures | None
    status: ExtractionStatus
    latency_s: float
    raw_output: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.features is not None


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a feature extractor for security alerts. "
    "You do not decide whether an alert is malicious or benign. "
    "You only report what the alert says, using the allowed values. "
    "Answer only from evidence present in the alert text. "
    "When the alert does not contain the information, use the value that "
    "denotes absence of evidence. "
    "Respond with a single JSON object and nothing else."
)

#: Doua formulari ale cererii, pentru poarta de dezacord (etapa 3).
#: Difera doar prin ordinea si prin modul de a cere dovada, nu prin
#: continut semantic -- altfel dezacordul masoara promptul, nu modelul.
PHRASINGS: dict[str, str] = {
    "a": (
        "Extract the features of the following alert.\n\n"
        "ALERT:\n{body}\n\n"
        "Answer with the JSON object."
    ),
    "b": (
        "Read the alert below. For each field, first locate the supporting "
        "fragment in the text, then choose the allowed value it supports. "
        "If no fragment supports a field, choose the value that denotes "
        "absence of evidence.\n\n"
        "ALERT:\n{body}\n\n"
        "Answer with the JSON object."
    ),
}


def build_alert_body(alert: NormalizedAlert) -> str:
    """
    Serializeaza alerta folosind numai ALLOWED_FIELDS.

    Functie pura, fara model, ca sa poata fi testata direct. Campurile
    absente se scriu explicit ca `<absent>`: modelul trebuie sa poata
    distinge "lipseste din telemetrie" de "nu se aplica", pentru ca in
    aval distinctia asta produce FP_DATA in loc de FP_LOGIC.
    """
    lines: list[str] = []
    for name in ALLOWED_FIELDS:
        value = getattr(alert, name, None)
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value) if value else None
        if value is None or value == "":
            rendered = "<absent>"
        else:
            rendered = str(value)
        lines.append(f"{name}: {rendered}")
    return "\n".join(lines)


def build_prompt(alert: NormalizedAlert, phrasing: str = "a") -> str:
    """Cererea de utilizator completa pentru o alerta."""
    if phrasing not in PHRASINGS:
        raise ValueError(f"formulare necunoscuta: {phrasing!r}")
    return PHRASINGS[phrasing].format(body=build_alert_body(alert))


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class Extractor:
    """
    Invelis peste llama.cpp. Incarca modelul o singura data, la prima
    utilizare.
    """

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        n_ctx: int = N_CTX,
        temperature: float = TEMPERATURE,
        n_gpu_layers: int = -1,
    ) -> None:
        self.model_path = model_path
        self.n_ctx = n_ctx
        self.temperature = temperature
        self.n_gpu_layers = n_gpu_layers
        self._llm: Any = None
        self._schema = flat_json_schema()

    @property
    def quantization(self) -> str:
        """Deduce cuantizarea din numele fisierului, pentru antetul raportului."""
        stem = self.model_path.rsplit("/", 1)[-1]
        for tag in ("Q8_0", "Q6_K", "Q5_K_M", "Q5_K_S", "Q4_K_M", "Q4_0", "F16"):
            if tag.lower() in stem.lower():
                return tag
        return "necunoscuta"

    def load(self) -> None:
        if self._llm is not None:
            return
        from llama_cpp import Llama  # import lazy: vezi antetul modulului

        self._llm = Llama(
            model_path=self.model_path,
            n_ctx=self.n_ctx,
            n_gpu_layers=self.n_gpu_layers,
            verbose=False,
        )

    def extract(self, alert: NormalizedAlert, phrasing: str = "a") -> ExtractionResult:
        """O singura extragere. Nu ridica exceptii: le codifica in status."""
        self.load()
        prompt = build_prompt(alert, phrasing)
        started = time.perf_counter()

        try:
            response = self._llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object", "schema": self._schema},
                temperature=self.temperature,
                max_tokens=MAX_TOKENS,
            )
        except Exception as exc:  # noqa: BLE001 -- statusul e rezultatul
            return ExtractionResult(
                alert_uuid=alert.alert_uuid,
                features=None,
                status="model_error",
                latency_s=time.perf_counter() - started,
                error=f"{type(exc).__name__}: {exc}",
            )

        latency = time.perf_counter() - started
        raw = (response["choices"][0]["message"]["content"] or "").strip()

        if not raw:
            return ExtractionResult(
                alert_uuid=alert.alert_uuid,
                features=None,
                status="empty_output",
                latency_s=latency,
            )

        try:
            features = AlertFeatures(**json.loads(raw))
        except Exception as exc:  # noqa: BLE001
            return ExtractionResult(
                alert_uuid=alert.alert_uuid,
                features=None,
                status="schema_invalid",
                latency_s=latency,
                raw_output=raw,
                error=f"{type(exc).__name__}: {exc}",
            )

        return ExtractionResult(
            alert_uuid=alert.alert_uuid,
            features=features,
            status="ok",
            latency_s=latency,
            raw_output=raw,
        )

    def extract_twice(
        self, alert: NormalizedAlert
    ) -> tuple[ExtractionResult, ExtractionResult, dict[str, bool]]:
        """
        Poarta de dezacord (etapa 3).

        Ruleaza aceeasi alerta cu doua formulari si raporteaza pe ce campuri
        raspunsurile coincid. Nu decide nimic aici -- decide.py alege ce
        face cu dezacordul. Alternativa la proxy-ul O-005, care e disponibil
        doar pe ramura de cod, nu si pe cea de alerte.
        """
        left = self.extract(alert, phrasing="a")
        right = self.extract(alert, phrasing="b")

        if not (left.ok and right.ok):
            agreement = {name: False for name in FEATURE_FIELDS}
        else:
            agreement = {
                name: getattr(left.features, name) == getattr(right.features, name)
                for name in FEATURE_FIELDS
            }

        return left, right, agreement

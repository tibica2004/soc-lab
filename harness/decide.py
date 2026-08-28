"""
Decizia -- cod determinist, zero model.

Modulul nu importa nimic din extract.py si nu incarca modelul. Arborele se
poate testa cu trasaturi scrise de mana, in milisecunde.

Regulile sunt DATE, nu `if`-uri inlantuite. Motivul e practic: ablatia pe
reguli devine o bucla peste submultimi, exact ca ablatia pe triagere din
harness-ul de pre-filtru. Cu `if`-uri, fiecare ablatie ar fi o rescriere.

Doua defecte ale arborelui anterior, reparate aici:

- regulile 1 si 2 cereau amandoua `TAMPERING_OR_ACCESS`, deci o singura
  trasatura decidea tot, iar celelalte doua erau moarte. Aici fiecare
  regula depinde de o combinatie distincta, si `fired_rule` iti spune care
  a decis efectiv -- daca o regula nu se aprinde niciodata, o vezi.
- `risk_score` era primit si ignorat. Aici intra intr-o regula reala
  (R5), care se poate dezactiva la ablatie ca sa masori cat aduce.

Vocabularul de verdicte urmeaza subclasele CORTEX. Distinctia care conteaza
pentru teza e FP_DATA vs FP_LOGIC: primul inseamna ca telemetria nu a livrat
contextul (command_line lipseste la 27% din alerte, O-002), al doilea ca
regula a fost prea larga. Sunt probleme diferite, cu solutii diferite, si
un sistem care le confunda nu poate spune care.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Sequence

from features import (
    ActionReversibility,
    AlertFeatures,
    CommandShape,
    NamingPattern,
    ParentLineage,
    TargetSensitivity,
)
from normalize import NormalizedAlert


class Verdict(str, Enum):
    ACTIONABLE = "actionable"
    BENIGN_POSITIVE = "benign_positive"
    FP_LOGIC = "fp_logic"
    FP_DATA = "fp_data"
    UNDETERMINED = "undetermined"


#: Verdictele care trimit alerta la un om.
ESCALATING: frozenset[Verdict] = frozenset({Verdict.ACTIONABLE})


@dataclass(frozen=True)
class Rule:
    rule_id: str
    verdict: Verdict
    predicate: Callable[[AlertFeatures, NormalizedAlert], bool]
    rationale: str


@dataclass
class Decision:
    verdict: Verdict
    fired_rule: str
    rationale: str

    @property
    def escalates(self) -> bool:
        return self.verdict in ESCALATING


# ---------------------------------------------------------------------------
# Regulile, in ordinea de evaluare. Prima care se potriveste castiga.
# ---------------------------------------------------------------------------

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="R0-no-telemetry",
        verdict=Verdict.FP_DATA,
        predicate=lambda f, a: f.command_shape is CommandShape.NO_COMMAND_LINE,
        rationale=(
            "Alerta nu are linie de comanda. Nu e o decizie despre continut, "
            "e o constatare despre telemetrie (O-002)."
        ),
    ),
    Rule(
        rule_id="R1-reverse-shell",
        verdict=Verdict.ACTIONABLE,
        predicate=lambda f, a: f.command_shape is CommandShape.REVERSE_SHELL,
        rationale="Conexiune interactiva iesita: nu are varianta benigna plauzibila.",
    ),
    Rule(
        rule_id="R2-credential-access",
        verdict=Verdict.ACTIONABLE,
        predicate=lambda f, a: (
            f.target_sensitivity is TargetSensitivity.CREDENTIAL_STORE
            and f.action_reversibility is not ActionReversibility.NO_EVIDENCE
        ),
        rationale="Atingerea depozitului de credentiale, cu dovada de actiune.",
    ),
    Rule(
        rule_id="R3-log-tampering",
        verdict=Verdict.ACTIONABLE,
        predicate=lambda f, a: (
            f.command_shape is CommandShape.LOG_MANIPULATION
            and f.action_reversibility is ActionReversibility.MODIFIES_SYSTEM_STATE
        ),
        rationale="Modificarea urmelor de audit sau istoric.",
    ),
    Rule(
        rule_id="R4-manual-persistence",
        verdict=Verdict.ACTIONABLE,
        predicate=lambda f, a: (
            f.command_shape is CommandShape.PERSISTENCE_MECHANISM
            and f.parent_lineage is ParentLineage.INTERACTIVE_SHELL
        ),
        rationale=(
            "Persistenta instalata dintr-o sesiune interactiva. Aceeasi actiune "
            "pornita de un scheduler e operare normala -- descendenta e trasatura "
            "care le separa."
        ),
    ),
    Rule(
        rule_id="R5-risk-threshold",
        verdict=Verdict.ACTIONABLE,
        predicate=lambda f, a: (
            a.risk_score >= 73
            and f.action_reversibility is ActionReversibility.MODIFIES_SYSTEM_STATE
            and f.parent_lineage is not ParentLineage.SCHEDULER_OR_SERVICE
        ),
        rationale=(
            "Prag determinist pe scorul de risc al regulii, conditionat de "
            "modificare de stare. Pragul 73 = 'high' in Elastic; e o alegere, "
            "nu o masuratoare, si de aceea regula e ablatabila."
        ),
    ),
    Rule(
        rule_id="R6-automated-package-management",
        verdict=Verdict.BENIGN_POSITIVE,
        predicate=lambda f, a: (
            f.command_shape is CommandShape.PACKAGE_MANAGEMENT
            and f.parent_lineage
            in (ParentLineage.SCHEDULER_OR_SERVICE, ParentLineage.PACKAGE_MANAGER)
        ),
        rationale="Intretinere de pachete pornita automat: comportament asteptat.",
    ),
    Rule(
        rule_id="R7-read-only-no-target",
        verdict=Verdict.FP_LOGIC,
        predicate=lambda f, a: (
            f.action_reversibility is ActionReversibility.READS_ONLY
            and f.target_sensitivity is TargetSensitivity.NO_SPECIFIC_TARGET
        ),
        rationale=(
            "Citire fara tinta identificabila: regula s-a aprins fara sa existe "
            "ceva de protejat. Fals pozitiv de logica de regula."
        ),
    ),
)


def decide(
    features: AlertFeatures | None,
    alert: NormalizedAlert,
    enabled_rules: Sequence[str] | None = None,
    agreement: dict[str, bool] | None = None,
    require_agreement_on: Sequence[str] = (),
) -> Decision:
    """
    Verdictul pentru o alerta.

    `features is None` inseamna extragere esuata -> UNDETERMINED. Nu
    inchidem automat ce nu am putut citi.

    `enabled_rules` restrange setul de reguli active, pentru ablatie.

    `agreement` vine din `Extractor.extract_twice`. Daca o trasatura
    listata in `require_agreement_on` difera intre formulari, alerta merge
    la om in loc sa fie inchisa. Poarta nu poate opri o escaladare: un om
    se uita oricum la ea.
    """
    if features is None:
        return Decision(
            verdict=Verdict.UNDETERMINED,
            fired_rule="-",
            rationale="Extragere esuata: nu exista fapte pe care sa se decida.",
        )

    active = RULES if enabled_rules is None else tuple(
        r for r in RULES if r.rule_id in set(enabled_rules)
    )

    decision = Decision(
        verdict=Verdict.BENIGN_POSITIVE,
        fired_rule="default",
        rationale=(
            "Nicio regula de escaladare nu s-a aprins. Implicitul e inchiderea, "
            "pentru ca modelul nu produce niciodata negative (TNR=0, faza B) -- "
            "abtinerea trebuie sa vina din cod."
        ),
    )

    for rule in active:
        if rule.predicate(features, alert):
            decision = Decision(rule.verdict, rule.rule_id, rule.rationale)
            break

    if agreement and require_agreement_on and not decision.escalates:
        disputed = [
            name
            for name in require_agreement_on
            if not agreement.get(name, True)
        ]
        if disputed:
            return Decision(
                verdict=Verdict.UNDETERMINED,
                fired_rule="gate-disagreement",
                rationale=(
                    "Cele doua formulari nu sunt de acord pe: "
                    + ", ".join(disputed)
                    + ". Nu inchidem automat pe o trasatura instabila."
                ),
            )

    return decision


def all_rule_ids() -> list[str]:
    return [r.rule_id for r in RULES]

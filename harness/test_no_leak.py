"""
Testul care apara masuratoarea de ea insasi.

Scurgerea din `evaluate.py` nu a fost o greseala de neatentie, a fost o
greseala usor de refacut: promptul se construia din acelasi dict ca
etichetarea. Testul asta face recidiva imposibila -- daca `technique_id`,
`label` sau `notes` reapar in prompt, pica.

Ruleaza fara model si fara llama_cpp:

    python3 test_no_leak.py
    # sau
    pytest test_no_leak.py -q
"""

from __future__ import annotations

import re

from features import (
    FEATURE_FIELDS,
    ActionReversibility,
    AlertFeatures,
    CommandShape,
    NamingPattern,
    ParentLineage,
    TargetSensitivity,
    flat_json_schema,
)
from decide import RULES, Verdict, all_rule_ids, decide
from extract import ALLOWED_FIELDS, build_alert_body, build_prompt
from normalize import NormalizedAlert

#: Coloanele de ground truth. Exista doar in CSV-urile noastre; o alerta
#: Elastic reala nu le contine. Daca ajung in prompt, modelul citeste
#: raspunsul in loc sa-l deduca.
GROUND_TRUTH_TOKENS = (
    "NOISE", "noise script", "Legitimate", "legitimate",
    "technique_id", "T1059", "T1078", "T1548", "T1136",
    "label", "notes", "expected_rules", "TP", "FP",
)


def _alert(**overrides) -> NormalizedAlert:
    base = dict(
        alert_uuid="uuid-1",
        timestamp="2026-08-20T12:10:36+03:00",
        rule_id="rule-1",
        rule_uuid="ruuid-1",
        rule_name="Linux User Account Creation",
        severity="medium",
        risk_score=47,
        is_building_block=False,
        reason="process event with useradd on tiberiu-VirtualBox",
        host_name="tiberiu-VirtualBox",
        user_name="root",
        process_name="useradd",
        process_command_line="useradd evil_user",
        process_parent_name="bash",
    )
    base.update(overrides)
    return NormalizedAlert(**base)


def _features(**overrides) -> AlertFeatures:
    base = dict(
        command_shape=CommandShape.ROUTINE_ADMIN,
        parent_lineage=ParentLineage.SCHEDULER_OR_SERVICE,
        naming_pattern=NamingPattern.CONVENTIONAL_SYSTEM,
        target_sensitivity=TargetSensitivity.NO_SPECIFIC_TARGET,
        action_reversibility=ActionReversibility.READS_ONLY,
        evidence_span="",
    )
    base.update(overrides)
    return AlertFeatures(**base)


# ---------------------------------------------------------------------------
# Scurgerea de eticheta
# ---------------------------------------------------------------------------


def test_prompt_uses_only_allowed_fields() -> None:
    """Corpul alertei nu contine campuri din afara listei albe."""
    forbidden = {"technique_id", "label", "notes", "expected_rules", "test_number"}
    assert not (set(ALLOWED_FIELDS) & forbidden)

    body = build_alert_body(_alert())
    for line in body.splitlines():
        name = line.split(":", 1)[0].strip()
        assert name in ALLOWED_FIELDS, f"camp neasteptat in prompt: {name}"


def test_prompt_contains_no_ground_truth_tokens() -> None:
    """
    Chiar daca cineva pune adnotari in `reason`, promptul nu are voie sa
    contina vocabularul cheii de raspuns.
    """
    for phrasing in ("a", "b"):
        prompt = build_prompt(_alert(), phrasing)
        for token in GROUND_TRUTH_TOKENS:
            # Potrivire pe cuvant intreg: altfel "denotes" din instructiuni
            # se raporteaza ca scurgere de "notes".
            pattern = rf"(?<![A-Za-z_]){re.escape(token)}(?![A-Za-z_])"
            assert not re.search(pattern, prompt), f"scurgere de eticheta: {token!r}"


def test_field_descriptions_are_class_neutral() -> None:
    """
    Descrierea unui camp nu are voie sa contina un sir care apare doar
    intr-o clasa. Asta invalidase schema anterioara.
    """
    for name, field_info in AlertFeatures.model_fields.items():
        text = (field_info.description or "")
        for token in ("NOISE", "noise script", "Legitimate", "benign_noise"):
            assert token not in text, f"{name}: descrierea contine {token!r}"


def test_missing_fields_render_as_absent() -> None:
    """Absenta telemetriei e explicita, nu tacuta."""
    body = build_alert_body(_alert(process_command_line=None))
    assert "process_command_line: <absent>" in body


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_flat_schema_has_no_refs() -> None:
    """Fara `$ref`/`$defs`, gramatica GBNF se genereaza previzibil."""
    schema = flat_json_schema()
    text = str(schema)
    assert "$ref" not in text and "$defs" not in text
    for name in FEATURE_FIELDS:
        assert schema["properties"][name]["enum"]


# ---------------------------------------------------------------------------
# Arborele
# ---------------------------------------------------------------------------


def test_extraction_failure_is_undetermined() -> None:
    """Ce nu s-a putut citi nu se inchide automat."""
    assert decide(None, _alert()).verdict is Verdict.UNDETERMINED


def test_missing_command_line_is_fp_data() -> None:
    """FP de date, nu de logica de regula."""
    decision = decide(
        _features(command_shape=CommandShape.NO_COMMAND_LINE), _alert()
    )
    assert decision.verdict is Verdict.FP_DATA


def test_reverse_shell_escalates() -> None:
    decision = decide(
        _features(command_shape=CommandShape.REVERSE_SHELL), _alert()
    )
    assert decision.verdict is Verdict.ACTIONABLE


def test_persistence_depends_on_lineage() -> None:
    """
    Aceeasi actiune, descendenta diferita, verdict diferit. Daca testul asta
    pica, arborele a redevenit dependent de o singura trasatura.
    """
    manual = decide(
        _features(
            command_shape=CommandShape.PERSISTENCE_MECHANISM,
            parent_lineage=ParentLineage.INTERACTIVE_SHELL,
        ),
        _alert(risk_score=21),
    )
    scheduled = decide(
        _features(
            command_shape=CommandShape.PERSISTENCE_MECHANISM,
            parent_lineage=ParentLineage.SCHEDULER_OR_SERVICE,
        ),
        _alert(risk_score=21),
    )
    assert manual.verdict is Verdict.ACTIONABLE
    assert scheduled.verdict is not Verdict.ACTIONABLE


def test_every_rule_is_reachable() -> None:
    """
    Fiecare regula trebuie sa se poata aprinde prima, altfel e cod mort --
    exact defectul arborelui anterior, unde doua reguli cereau aceeasi
    conditie si a doua nu se atingea niciodata.
    """
    cases = {
        "R0-no-telemetry": (
            _features(command_shape=CommandShape.NO_COMMAND_LINE), _alert()),
        "R1-reverse-shell": (
            _features(command_shape=CommandShape.REVERSE_SHELL), _alert()),
        "R2-credential-access": (
            _features(
                target_sensitivity=TargetSensitivity.CREDENTIAL_STORE,
                action_reversibility=ActionReversibility.READS_ONLY,
            ), _alert()),
        "R3-log-tampering": (
            _features(
                command_shape=CommandShape.LOG_MANIPULATION,
                action_reversibility=ActionReversibility.MODIFIES_SYSTEM_STATE,
            ), _alert()),
        "R4-manual-persistence": (
            _features(
                command_shape=CommandShape.PERSISTENCE_MECHANISM,
                parent_lineage=ParentLineage.INTERACTIVE_SHELL,
            ), _alert(risk_score=21)),
        "R5-risk-threshold": (
            _features(
                action_reversibility=ActionReversibility.MODIFIES_SYSTEM_STATE,
                parent_lineage=ParentLineage.INTERACTIVE_SHELL,
            ), _alert(risk_score=99)),
        "R6-automated-package-management": (
            _features(
                command_shape=CommandShape.PACKAGE_MANAGEMENT,
                parent_lineage=ParentLineage.PACKAGE_MANAGER,
            ), _alert(risk_score=21)),
        "R7-read-only-no-target": (
            _features(), _alert(risk_score=21)),
    }
    assert set(cases) == set(all_rule_ids()), "test nesincronizat cu RULES"
    for rule_id, (features, alert) in cases.items():
        assert decide(features, alert).fired_rule == rule_id, rule_id


def test_disagreement_gate_blocks_autoclose_only() -> None:
    """Poarta trimite la om ce ar fi fost inchis; nu opreste o escaladare."""
    disagree = {name: False for name in FEATURE_FIELDS}

    closed = decide(_features(), _alert(risk_score=21), agreement=disagree,
                    require_agreement_on=FEATURE_FIELDS)
    assert closed.verdict is Verdict.UNDETERMINED

    escalated = decide(
        _features(command_shape=CommandShape.REVERSE_SHELL), _alert(),
        agreement=disagree, require_agreement_on=FEATURE_FIELDS,
    )
    assert escalated.verdict is Verdict.ACTIONABLE


def test_rule_ablation_changes_outcome() -> None:
    """Regulile sunt date: dezactivarea uneia se vede in verdict."""
    features = _features(
        action_reversibility=ActionReversibility.MODIFIES_SYSTEM_STATE,
        parent_lineage=ParentLineage.INTERACTIVE_SHELL,
    )
    alert = _alert(risk_score=99)
    assert decide(features, alert).verdict is Verdict.ACTIONABLE
    without = [r for r in all_rule_ids() if r != "R5-risk-threshold"]
    assert decide(features, alert, enabled_rules=without).verdict is not Verdict.ACTIONABLE


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok    {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {name}: {exc}")
    print(f"\n{failures} esecuri" if failures else "\nToate testele trec.")
    raise SystemExit(1 if failures else 0)

"""
Schema de trasaturi -- stratul de extragere.

Fiecare camp e o intrebare inchisa. Regula de proiectare, din care nu se
face rabat:

    o intrebare e valida doar daca un caz benign si unul malitios sunt
    OBLIGATE sa raspunda diferit.

Daca o valoare poate fi ghicita dintr-un prior generic, fara sa te uiti la
alerta, intrebarea nu poarta semnal. Asa a esuat "was prior activity
related?": si zgomotul, si atacul aveau activitate precedenta, deci
raspunsul era "yes" in ambele cazuri.

A doua regula, la fel de importanta: NICIO descriere de camp nu are voie sa
contina un sir care apare doar intr-o clasa. Descrierea care spunea
"if it explicitly says 'NOISE', choose benign_noise" nu cerea extragere,
cerea copierea cheii de raspuns. Vezi test_no_leak.py.

Fiecare enum are o valoare pentru absenta dovezii. "Nu stiu" si "nimic
suspect" sunt lucruri diferite si trebuie sa fie separabile in aval:
`command_line` lipseste la 27% din alerte (O-002), iar acele cazuri sunt
fals-pozitive de DATE, nu de logica.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CommandShape(str, Enum):
    """Forma comenzii executate, dedusa din linia de comanda."""

    REVERSE_SHELL = "reverse_shell"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    LOG_MANIPULATION = "log_manipulation"
    PACKAGE_MANAGEMENT = "package_management"
    ROUTINE_ADMIN = "routine_admin"
    NO_COMMAND_LINE = "no_command_line"


class ParentLineage(str, Enum):
    """Ce a pornit procesul."""

    INTERACTIVE_SHELL = "interactive_shell"
    SCHEDULER_OR_SERVICE = "scheduler_or_service"
    PACKAGE_MANAGER = "package_manager"
    UNKNOWN_PARENT = "unknown_parent"


class NamingPattern(str, Enum):
    """
    Tiparul de denumire al identificatorilor din comanda (utilizatori,
    fisiere, servicii).

    Singura trasatura care a separat perfect clasele in testul din
    2026-08-26. Merita pastrata si masurata separat.
    """

    GENERIC_OR_TEST_LIKE = "generic_or_test_like"
    CONVENTIONAL_SYSTEM = "conventional_system"
    ORGANIZATION_SPECIFIC = "organization_specific"
    NO_IDENTIFIERS = "no_identifiers"


class TargetSensitivity(str, Enum):
    """Ce resursa atinge actiunea."""

    CREDENTIAL_STORE = "credential_store"
    SCHEDULING_OR_SERVICE_CONFIG = "scheduling_or_service_config"
    AUDIT_OR_HISTORY = "audit_or_history"
    APPLICATION_DATA = "application_data"
    NO_SPECIFIC_TARGET = "no_specific_target"


class ActionReversibility(str, Enum):
    """Daca actiunea modifica starea sistemului sau doar o citeste."""

    MODIFIES_SYSTEM_STATE = "modifies_system_state"
    READS_ONLY = "reads_only"
    NO_EVIDENCE = "no_evidence"


class AlertFeatures(BaseModel):
    """
    Faptele extrase dintr-o alerta. NU contine verdict.

    Verdictul se calculeaza in decide.py, din aceste campuri, in cod
    determinist. Modelul nu eticheteaza niciodata.
    """

    command_shape: CommandShape = Field(
        description=(
            "The shape of the executed command line. "
            "reverse_shell: opens an outbound interactive connection. "
            "credential_access: reads or copies password, shadow, key or token material. "
            "persistence_mechanism: installs a scheduled job, service or startup entry. "
            "log_manipulation: clears, truncates or rewrites logs or shell history. "
            "package_management: installs, updates or removes software packages. "
            "routine_admin: any other ordinary administrative operation. "
            "no_command_line: the alert carries no command line at all."
        )
    )
    parent_lineage: ParentLineage = Field(
        description=(
            "What started the process. "
            "interactive_shell: a shell attached to a session. "
            "scheduler_or_service: cron, systemd, or another automated supervisor. "
            "package_manager: apt, dpkg, yum or similar. "
            "unknown_parent: the parent is absent or unrecognisable."
        )
    )
    naming_pattern: NamingPattern = Field(
        description=(
            "The naming style of identifiers appearing in the command "
            "(user names, file names, service names). "
            "generic_or_test_like: placeholder-style or sequential names. "
            "conventional_system: standard operating system names. "
            "organization_specific: names that follow a local convention. "
            "no_identifiers: the command contains no identifiers."
        )
    )
    target_sensitivity: TargetSensitivity = Field(
        description=(
            "Which resource the action touches. "
            "credential_store: password, shadow, key or token storage. "
            "scheduling_or_service_config: cron tables, unit files, init scripts. "
            "audit_or_history: audit logs or shell history. "
            "application_data: files owned by an application. "
            "no_specific_target: no resource is identifiable."
        )
    )
    action_reversibility: ActionReversibility = Field(
        description=(
            "Whether the action changes system state. "
            "modifies_system_state: writes, deletes, creates or changes permissions. "
            "reads_only: only reads or lists. "
            "no_evidence: the alert does not say."
        )
    )
    evidence_span: str = Field(
        default="",
        description=(
            "The exact fragment of the alert the answers are based on. "
            "Copy it verbatim. If nothing supports the answers, leave it empty."
        ),
    )


#: Campurile care intra in tabelele de contingenta. `evidence_span` e text
#: liber, nu categorie -- e pentru audit, nu pentru masuratoare.
FEATURE_FIELDS: tuple[str, ...] = (
    "command_shape",
    "parent_lineage",
    "naming_pattern",
    "target_sensitivity",
    "action_reversibility",
)


def flat_json_schema() -> dict[str, Any]:
    """
    Schema JSON cu enumurile expandate inline, fara `$ref` si `$defs`.

    `AlertFeatures.model_json_schema()` produce referinte catre `$defs`.
    Convertorul de gramatica GBNF din llama.cpp le suporta inconsistent
    intre versiuni si esueaza tacut, ceea ce anuleaza tocmai garantia
    pentru care folosim decodare constransa. Schema plata elimina riscul.
    """
    properties: dict[str, Any] = {}
    for name, field_info in AlertFeatures.model_fields.items():
        annotation = field_info.annotation
        if isinstance(annotation, type) and issubclass(annotation, Enum):
            properties[name] = {
                "type": "string",
                "enum": [member.value for member in annotation],
                "description": field_info.description or "",
            }
        else:
            properties[name] = {
                "type": "string",
                "description": field_info.description or "",
            }

    return {
        "type": "object",
        "properties": properties,
        "required": list(FEATURE_FIELDS),
        "additionalProperties": False,
    }

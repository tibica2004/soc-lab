"""
Extractor determinist -- bratul de control.

Produce EXACT aceleasi `AlertFeatures` ca `extract.Extractor`, dar prin regex
si potriviri de nume, fara model. Interfata e identica, deci `bench.py` poate
comuta intre ele cu un singur argument, si tot restul lantului (arbore,
etichetare, metrici) ramane neschimbat.

La ce foloseste. Rularea din 2026-08-28 pe 115 alerte a dat TNR 96% dar 3/5
atacuri ratate, sub baseline-ul determinist `prefilter_safe` (0/5). Din
acel rezultat singur nu se poate spune care strat e de vina:

    (a) schema de trasaturi nu poate exprima diferenta atac / zgomot,
        caz in care arhitectura extract-then-decide e gresita aici;
    (b) schema e buna, dar Antares nu o poate popula pe intrare de tip
        alerta, caz in care gatuirea e modelul.

Bratul asta separa cele doua. Aceleasi campuri, acelasi arbore, alta sursa
de trasaturi.

LIMITARE IMPORTANTA, de scris in raport: regulile de mai jos sunt formulate
DUPA ce am vazut alertele din laborator. Sunt deci optimist partinitoare --
un extractor scris orb ar merge mai prost. Bratul asta NU e un competitor
onest si nu se raporteaza ca "solutie fara LLM". E o margine superioara
pentru stratul de trasaturi: daca nici cu extragere aproape-oracol arborele
nu bate `prefilter_safe`, atunci ipoteza (a) e adevarata si nicio
imbunatatire a modelului nu ajuta.
"""

from __future__ import annotations

import re
import time

from extract import ExtractionResult
from features import AlertFeatures, CommandShape, NamingPattern, ParentLineage
from normalize import NormalizedAlert

# ---------------------------------------------------------------------------
# command_shape
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = (
    r"/etc/shadow", r"/etc/gshadow", r"/etc/security/opasswd",
    r"\bunshadow\b", r"id_rsa", r"id_ed25519", r"\.ssh/", r"authorized_keys",
    r"\.aws/credentials", r"\bkeyring\b",
)

LOG_PATTERNS = (
    r"\.bash_history", r"\.zsh_history", r"/var/log/", r"\bhistory\s+-c\b",
    r"\bshred\b", r"\bjournalctl\b.*--vacuum", r">\s*/dev/null.*history",
    r"\btruncate\b.*log", r"\bwtmp\b", r"\butmp\b", r"\blastlog\b",
)

PERSISTENCE_PATTERNS = (
    r"\bcrontab\b", r"/etc/cron", r"\bat\s+now\b",
    r"\bsystemctl\s+(enable|link)\b", r"\.service\b", r"/etc/rc\.local",
    r"\buseradd\b", r"\badduser\b", r"\busermod\b", r"\bgroupadd\b",
    r"chmod\s+[ug]\+s", r"chmod\s+[0-7]?[24][0-7]{3}",  # SUID/SGID
    r"\.bashrc", r"\.profile", r"/etc/ld\.so\.preload",
)

PACKAGE_PATTERNS = (
    r"\bapt(-get)?\b", r"\bdpkg\b", r"\byum\b", r"\bdnf\b", r"\bsnap\b",
    r"\bunattended-upgrade", r"\bpip3?\s+install\b",
)


def _matches(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def command_shape_of(alert: NormalizedAlert) -> CommandShape:
    cmd = alert.process_command_line
    if not cmd:
        return CommandShape.NO_COMMAND_LINE
    # Ordinea conteaza: o comanda poate cadea sub mai multe tipare.
    # Accesul la credentiale si stergerea urmelor primeaza asupra
    # persistentei, iar persistenta asupra intretinerii de pachete.
    if _matches(cmd, CREDENTIAL_PATTERNS):
        return CommandShape.CREDENTIAL_ACCESS
    if _matches(cmd, LOG_PATTERNS):
        return CommandShape.LOG_MANIPULATION
    if _matches(cmd, PERSISTENCE_PATTERNS):
        return CommandShape.PERSISTENCE_MECHANISM
    if _matches(cmd, PACKAGE_PATTERNS):
        return CommandShape.PACKAGE_MANAGEMENT
    return CommandShape.ROUTINE_ADMIN


# ---------------------------------------------------------------------------
# parent_lineage
# ---------------------------------------------------------------------------

INTERACTIVE_PARENTS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh",
                       "sudo", "su", "login", "sshd", "gnome-terminal-"}
SCHEDULER_PARENTS = {"cron", "crond", "anacron", "atd", "systemd",
                     "systemd-run", "init", "supervisord"}
PACKAGE_PARENTS = {"apt", "apt-get", "dpkg", "unattended-upgrade",
                   "yum", "dnf", "snapd"}


def parent_lineage_of(alert: NormalizedAlert) -> ParentLineage:
    parent = (alert.process_parent_name or "").lower()
    if not parent:
        return ParentLineage.UNKNOWN_PARENT
    if parent in PACKAGE_PARENTS:
        return ParentLineage.PACKAGE_MANAGER
    if parent in SCHEDULER_PARENTS or parent.startswith("systemd"):
        return ParentLineage.SCHEDULER_OR_SERVICE
    if parent in INTERACTIVE_PARENTS:
        return ParentLineage.INTERACTIVE_SHELL
    return ParentLineage.UNKNOWN_PARENT


# ---------------------------------------------------------------------------
# naming_pattern
# ---------------------------------------------------------------------------

GENERIC_TOKENS = (
    r"\bart\b", r"atomic", r"\btest", r"\btmp\b", r"/tmp/", r"\bfoo\b",
    r"\bbar\b", r"\bevil", r"\bhello\b", r"\buser[0-9]+\b", r"\bdemo\b",
    r"\bsample\b", r"\bexample\b", r"[a-z]+_?[0-9]{1,3}\b",
)

IDENTIFIER_RE = re.compile(r"(/[\w.\-/]+|\b[\w.\-]+@[\w.\-]+\b|\b\w+_\w+\b)")


def naming_pattern_of(alert: NormalizedAlert) -> NamingPattern:
    cmd = alert.process_command_line or ""
    if not IDENTIFIER_RE.search(cmd):
        return NamingPattern.NO_IDENTIFIERS
    if _matches(cmd, GENERIC_TOKENS):
        return NamingPattern.GENERIC_OR_TEST_LIKE
    if re.search(r"^/(etc|usr|bin|sbin|var|lib|proc|sys)/", cmd) or re.search(
        r"\s/(etc|usr|bin|sbin|var|lib|proc|sys)/", cmd
    ):
        return NamingPattern.CONVENTIONAL_SYSTEM
    return NamingPattern.CONVENTIONAL_SYSTEM


# ---------------------------------------------------------------------------
# Interfata identica cu extract.Extractor
# ---------------------------------------------------------------------------


class DeterministicExtractor:
    """Aceeasi semnatura ca `Extractor`, ca `bench.py` sa poata comuta."""

    model_path = "(determinist -- fara model)"
    quantization = "n/a"
    temperature = 0.0
    n_ctx = 0

    def load(self) -> None:  # pragma: no cover -- exista doar pentru simetrie
        return

    def extract(
        self, alert: NormalizedAlert, phrasing: str = "a"
    ) -> ExtractionResult:
        started = time.perf_counter()
        features = AlertFeatures(
            command_shape=command_shape_of(alert),
            parent_lineage=parent_lineage_of(alert),
            naming_pattern=naming_pattern_of(alert),
            evidence_span=alert.process_command_line or "",
        )
        return ExtractionResult(
            alert_uuid=alert.alert_uuid,
            features=features,
            status="ok",
            latency_s=time.perf_counter() - started,
            raw_output=features.model_dump_json(),
        )

    def extract_twice(self, alert: NormalizedAlert):
        """Determinist: cele doua ramuri coincid mereu, prin constructie."""
        from features import FEATURE_FIELDS

        result = self.extract(alert)
        return result, result, {name: True for name in FEATURE_FIELDS}

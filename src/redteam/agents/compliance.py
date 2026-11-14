"""Agent 4 — Compliance Breaker : relie les faiblesses observées aux exigences DORA, MiCA, AI Act, RGPD.

SOCLE posé par Joseph, à étendre par Paul-Edmond (voir docs/AGENT4_GUIDE.md).
Un contrôle = une fonction `check_xxx(snapshot, results) -> Finding | None` ajoutée à CHECKS.
- `snapshot` : état d'ARMS après les attaques (config, journal de décisions, événements, fournisseurs)
- `results`  : résultats des agents précédents (Reconnaissance, Attaquant, IA Adversaire)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .base import AgentResult, RedTeamAgent


@dataclass
class Finding:
    id: str
    regulation: str          # DORA | MiCA | AI Act | RGPD | LCB-FT
    reference: str           # article
    title: str
    evidence: str            # fait mesuré, jamais une supposition
    severity: str            # Critique | Haute | Moyenne
    linked_scenarios: list[str]
    recommendation: str


# --- Contrôles du socle -------------------------------------------------------

def check_dora_third_party(snapshot, results):
    crit = [v for v in snapshot["vendors"] if v["critical"] and (v["alternatives"] == 0 or not v["exit_plan"])]
    if not crit:
        return None
    names = ", ".join(f"{v['name']} ({v['service']})" for v in crit)
    return Finding("DORA-28", "DORA", "art. 28 (risque lié aux prestataires TIC tiers, stratégies de sortie)",
                   "Dépendances TIC critiques non maîtrisées",
                   f"{len(crit)} prestataire(s) critique(s) sans alternative ou sans plan de sortie : {names}",
                   "Critique", ["A3"],
                   "Registre d'information des prestataires TIC, 2e source de prix, stratégie de sortie testée par prestataire critique")


def check_mica_custody(snapshot, results):
    cust = snapshot["config"]["crypto_custody"]
    attack = next((r for r in results["Attaquant"].data["runs"] if r["scenario"] == "A3"), None)
    issues = []
    if not cust["segregated_client_assets"]:
        issues.append("actifs clients non ségrégués")
    if cust["wallet"] == "hot" and not cust["multisig"]:
        issues.append("hot wallet mono-signature")
    if attack and not attack["detected"]:
        issues.append(f"retrait valorisé {attack['booked_value_eur']:,.0f} € pour une valeur réelle de {attack['real_value_eur']:,.0f} €".replace(",", " "))
    if not issues:
        return None
    return Finding("MiCA-75", "MiCA", "art. 75 (garde et administration de crypto-actifs, ségrégation 75(7), responsabilité 75(8))",
                   "Gestion des actifs crypto non sécurisée", " ; ".join(issues), "Critique", ["A3"],
                   "Ségrégation des adresses clients, multisig/MPC, prix signé multi-sources avec contrôle d'écart avant tout retrait")


def check_ai_traceability(snapshot, results):
    log = snapshot["decision_log"]
    if not log:
        return None
    no_reason = sum(1 for d in log if "rationale" not in d)
    no_version = snapshot["config"]["decision_log"]["stores_model_version"] is False
    share = no_reason / len(log)
    if share < 0.05 and not no_version:
        return None
    return Finding("AIACT-12", "AI Act", "art. 12 (journalisation) et 13 (transparence) ; RGPD art. 22",
                   "Décisions clés non traçables ni explicables",
                   f"{no_reason}/{len(log)} décisions ({share:.0%}) sans justification ; version du modèle jamais journalisée",
                   "Haute", ["A1", "B1"],
                   "Journaliser pour CHAQUE décision : entrées, score, règles, version du modèle, justification lisible")


def check_ai_data_governance(snapshot, results):
    retraining = snapshot["config"]["retraining"]
    issues = []

    if not retraining["human_validation"]:
        issues.append("réentraînement sans validation humaine")

    if not retraining["model_versioning"]:
        issues.append("absence de versionnage du modèle")

    if not issues:
        return None

    adversary = results.get("IA Adversaire")
    attack = None

    if adversary is not None:
        attack = next(
            (run for run in adversary.data["runs"]
             if run["scenario"] == "B2"),
            None,
        )

    linked_scenarios = []

    if attack is not None:
        before = attack["recall_before"]["corridor_AE"]
        after = attack["recall_after"]["corridor_AE"]
        issues.append(
            f"B2 : détection des fraudes du corridor AE "
            f"avant = {before:.1%}, après = {after:.1%}"
        )
        linked_scenarios.append("B2")

    return Finding(
        id="AIACT-10",
        regulation="AI Act",
        reference="art. 10 et 15 — applicabilité à confirmer selon la classification",
        title="Réentraînement du modèle insuffisamment encadré",
        evidence=" ; ".join(issues),
        severity="Critique",
        linked_scenarios=linked_scenarios,
        recommendation=(
            "Valider les données de réentraînement, exiger une approbation "
            "humaine, versionner le modèle et vérifier ses performances "
            "avant activation, avec possibilité de retour arrière."
        ),
    )

def check_dora_detection(snapshot, results):
    undetected = []

    for agent_name in ("Attaquant", "IA Adversaire"):
        agent_result = results.get(agent_name)
        if agent_result is None:
            continue

        for run in agent_result.data["runs"]:
            if run.get("detected") is False:
                undetected.append(run["scenario"])

    if not undetected:
        return None

    scenarios = sorted(set(undetected))
    event_count = len(snapshot["monitoring_events"])

    return Finding(
        id="DORA-10",
        regulation="DORA",
        reference="art. 10 et 17 — détection et gestion des incidents",
        title="Scénarios d'attaque non détectés",
        evidence=(
            f"{len(scenarios)} scénario(s) déclaré(s) non détecté(s) : "
            f"{', '.join(scenarios)}. "
            f"Événements de surveillance présents : {event_count}. "
            "Aucun registre d'incidents fourni dans le snapshot : "
            "ouverture d'incident non vérifiable."
        ),
        severity="Critique",
        linked_scenarios=scenarios,
        recommendation=(
            "Ajouter des mécanismes de détection adaptés aux scénarios, "
            "relier les alertes aux attaques et tracer la qualification "
            "ainsi que le traitement des incidents."
        ),
    )

def check_rgpd_minimisation(snapshot, results):
    log = snapshot["decision_log"]
    config = snapshot["config"]["decision_log"]
    issues = []

    iban_count = sum(1 for entry in log if entry.get("iban"))
    name_count = sum(1 for entry in log if entry.get("holder_name"))

    if not config["pseudonymised"]:
        if iban_count:
            issues.append(f"{iban_count} entrée(s) contenant un IBAN en clair")
        if name_count:
            issues.append(f"{name_count} entrée(s) contenant un nom en clair")

    if config["retention_days"] is None:
        issues.append("aucune durée de conservation configurée")

    if not issues:
        return None

    return Finding(
        id="RGPD-5",
        regulation="RGPD",
        reference="art. 5(1)(c) et 5(1)(e) — minimisation et conservation",
        title="Données personnelles et conservation du journal à encadrer",
        evidence=" ; ".join(issues),
        severity="Haute",
        linked_scenarios=[],
        recommendation=(
            "Justifier les données nécessaires au journal, supprimer ou "
            "pseudonymiser les identifiants inutiles, définir une durée "
            "de conservation justifiée et automatiser la purge."
        ),
    )

#  TODO Paul (voir docs/AGENT4_GUIDE.md) :
#   check_ai_data_governance  (AI Act art. 10/15 : réentraînement sans validation, résultat B2)
#   check_human_oversight      (AI Act art. 14 : blocage automatique, revue des seules alertes)
#   check_rgpd_minimisation    (RGPD art. 5.1.c et 32 : IBAN et nom en clair, aucune durée de conservation)
#   check_dora_detection       (DORA art. 10 et 17 : attaques non détectées, aucun incident ouvert)
#   check_ai_act_classification (AI Act annexe III 5(b) : exclusion « détection de fraude », à justifier)
CHECKS = [
    check_dora_third_party,
    check_mica_custody,
    check_ai_traceability,
    check_ai_data_governance,
    check_dora_detection,
    check_rgpd_minimisation,
]


class ComplianceBreakerAgent(RedTeamAgent):
    name = "Compliance Breaker"
    role = "Identifier formellement les infractions réglementaires révélées par la Red Team"
    instructions = [
        "Tu es l'agent Compliance Breaker d'une Red Team autorisée.",
        "Relie chaque constat à un article précis (DORA, MiCA, AI Act, RGPD) et cite la preuve mesurée.",
        "Signale les gaps réglementaires non anticipés (ex. classification AI Act du système).",
    ]

    def execute(self, ctx: dict) -> AgentResult:
        snapshot = ctx["arms"].snapshot()
        findings = []
        for check in CHECKS:
            f = check(snapshot, ctx["results"])
            if f:
                findings.append(asdict(f))
        data = {"findings": findings, "checks_run": [c.__name__ for c in CHECKS],
                "by_regulation": {r: sum(1 for f in findings if f["regulation"] == r) for r in sorted({f["regulation"] for f in findings})}}
        narrative, engine, errors = self.narrate(ctx, data, "Présente les non-conformités par réglementation, avec article, preuve et correctif.")
        return AgentResult(self.name, data, narrative, engine, errors)

    def offline_narrative(self, data: dict) -> str:
        return "\n".join(f"- **{f['id']}** ({f['reference']}) — {f['title']} : {f['evidence']}" for f in data["findings"])

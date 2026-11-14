"""Agent 5 — Impact & Risk Scoring : perte financière, risque réglementaire, réputation → score 0-1 et priorités.

Méthode (transparente et reproductible) :
  impact      = 0,40 × financier + 0,35 × réglementaire + 0,25 × réputation   (chaque axe ∈ [0, 1])
  financier   = min(1, montant exposé mesuré / 500 000 €)
  réglem.     = gravité max des constats liés (Critique 1,0 · Haute 0,7 · Moyenne 0,4)
  réputation  = barème par type d'incident (LCB-FT 0,9 · perte d'actifs clients 0,8 · biais IA 0,7 · traçabilité 0,5)
  probabilité = 1,0 si l'attaque n'a déclenché aucune alerte, 0,3 sinon
  risque      = probabilité × impact → Élevé ≥ 0,60 · Moyen ≥ 0,35 · Faible sinon
"""

from __future__ import annotations

from .base import AgentResult, RedTeamAgent

SEVERITY = {"Critique": 1.0, "Haute": 0.7, "Moyenne": 0.4}
FIN_CAP = 500_000.0

VULNS = {
    "A1": ("Fractionnement multi-comptes non détecté (LCB-FT)", "amount_eur", 0.9),
    "A3": ("Manipulation du prix crypto : retrait sous-évalué", "loss_eur", 0.8),
    "B1": ("Évasion du modèle de fraude par perturbation", "evaded_amount_eur", 0.7),
    "B2": ("Empoisonnement ciblé : biais sur un corridor", "missed_fraud_eur", 0.7),
}


def level(score: float) -> str:
    return "Élevé" if score >= 0.60 else "Moyen" if score >= 0.35 else "Faible"


class ImpactRiskAgent(RedTeamAgent):
    name = "Impact & Risk"
    role = "Mesurer les conséquences des attaques et hiérarchiser les vulnérabilités pour le COMEX"
    instructions = [
        "Tu es l'agent Impact & Risk Scoring d'une Red Team autorisée.",
        "Explique le score de chaque vulnérabilité à partir des trois axes fournis, sans modifier les chiffres.",
        "Termine par une synthèse COMEX de 4 phrases maximum.",
    ]

    def execute(self, ctx: dict) -> AgentResult:
        runs = {r["scenario"]: r for agent in ("Attaquant", "IA Adversaire") for r in ctx["results"][agent].data["runs"]}
        findings = ctx["results"]["Compliance Breaker"].data["findings"]
        scored = []
        for sid, (title, amount_key, reputation) in VULNS.items():
            run = runs.get(sid)
            if not run:
                continue
            exposure = float(run.get(amount_key) or 0.0)
            linked = [f for f in findings if sid in f["linked_scenarios"]]
            reg = max((SEVERITY[f["severity"]] for f in linked), default=0.4)
            fin = min(1.0, exposure / FIN_CAP)
            impact = 0.40 * fin + 0.35 * reg + 0.25 * reputation
            likelihood = 0.3 if run["detected"] else 1.0
            risk = round(likelihood * impact, 3)
            scored.append({"id": sid, "title": title, "detected": run["detected"], "exposure_eur": round(exposure, 2),
                           "financial": round(fin, 3), "regulatory": reg, "reputation": reputation,
                           "likelihood": likelihood, "risk_score": risk, "level": level(risk),
                           "findings": [f["id"] for f in linked]})
        for f in findings:  # constats sans scénario chiffré : risque réglementaire pur
            if not any(f["id"] in s["findings"] for s in scored):
                reg = SEVERITY[f["severity"]]
                risk = round(0.35 * reg + 0.25 * 0.5, 3)
                scored.append({"id": f["id"], "title": f["title"], "detected": None, "exposure_eur": 0.0, "financial": 0.0,
                               "regulatory": reg, "reputation": 0.5, "likelihood": 1.0, "risk_score": risk, "level": level(risk),
                               "findings": [f["id"]]})
        scored.sort(key=lambda s: s["risk_score"], reverse=True)
        global_score = round(max((s["risk_score"] for s in scored), default=0.0) * 0.6 + (sum(s["risk_score"] for s in scored) / max(1, len(scored))) * 0.4, 3)
        data = {"vulnerabilities": scored, "global_risk_score": global_score, "global_level": level(global_score),
                "total_exposure_eur": round(sum(s["exposure_eur"] for s in scored), 2),
                "method": "impact = 0,40·financier + 0,35·réglementaire + 0,25·réputation ; risque = probabilité × impact"}
        narrative, engine, errors = self.narrate(ctx, data, "Explique le classement des vulnérabilités et rédige la synthèse COMEX.")
        return AgentResult(self.name, data, narrative, engine, errors)

    def offline_narrative(self, data: dict) -> str:
        rows = "\n".join(f"| {i} | {v['title']} | {v['exposure_eur']:,.0f} € | {v['risk_score']:.2f} | {v['level']} |".replace(",", " ")
                         for i, v in enumerate(data["vulnerabilities"], 1))
        return (f"| # | Vulnérabilité | Exposition | Score | Niveau |\n|---|---|---|---|---|\n{rows}\n\n"
                f"**Score global : {data['global_risk_score']:.2f} ({data['global_level']})** — ARMS n'est pas prêt pour la production.")

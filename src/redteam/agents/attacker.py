"""Agent 2 — Attaquant : scénarios cyber/LCB-FT « conventionnels » à forte probabilité."""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..arms.data import Transaction
from .base import AgentResult, RedTeamAgent

CATALOGUE = {
    "A0": "Contrôle de référence : un virement unique de 38 000 € (doit être détecté)",
    "A1": "Fractionnement multi-comptes (smurfing) : 6 comptes mules × 2 virements de 9 500 € vers un même bénéficiaire offshore",
    "A2": "Fractionnement naïf sur un seul compte : 3 virements de 9 500 € (doit être détecté)",
    "A3": "Manipulation du flux de prix crypto : prix BTC injecté à -90 % puis retrait sous le plafond",
}
MANDATORY = ["A0", "A1", "A3"]


class AttackPlan(BaseModel):
    scenarios: list[str] = Field(description="Identifiants de scénarios choisis dans le catalogue, par ordre d'exécution")
    rationale: str = Field(description="Justification courte du choix, liée aux vecteurs de la reconnaissance")


def run_A0(arms) -> dict:
    r = arms.process(Transaction("A0-1", "ACC-CTRL", 38_000, 15, "FR", beneficiary="BEN-X"))
    return {"scenario": "A0", "tx_sent": 1, "amount_eur": 38_000, "alerts": int(r["alert"]), "detected": r["alert"], "loss_eur": 0.0}


def run_A1(arms) -> dict:
    alerts, sent, total = 0, 0, 0.0
    for m in range(6):
        for k in range(2):
            tx = Transaction(f"A1-{m}-{k}", f"ACC-MULE-{m}", 9_500, 10 + k, "FR", beneficiary="BEN-OFFSHORE", ts=k * 2.0)
            r = arms.process(tx)
            alerts += int(r["alert"])
            sent += 1
            total += tx.amount_eur
    detected = alerts > 0
    return {"scenario": "A1", "tx_sent": sent, "amount_eur": total, "alerts": alerts, "detected": detected,
            "loss_eur": 0.0 if detected else total,
            "breakpoint": None if detected else "la règle R2 n'agrège que par compte, jamais par bénéficiaire : 6 comptes × 2 virements (114 000 €) passent sous le radar"}


def run_A2(arms) -> dict:
    alerts = sum(int(arms.process(Transaction(f"A2-{k}", "ACC-SOLO", 9_500, 10 + k, "FR", ts=k * 2.0))["alert"]) for k in range(3))
    return {"scenario": "A2", "tx_sent": 3, "amount_eur": 28_500, "alerts": alerts, "detected": alerts > 0, "loss_eur": 0.0}


def run_A3(arms) -> dict:
    market = arms.prices["BTC"]
    arms.ingest_price("BTC", market * 0.10, source="rogue-feed")
    events_before = len(arms.monitoring_events)
    r = arms.crypto_withdrawal("ACC-CRYPTO-7", "BTC", 8.0, market_price_eur=market)
    arms.ingest_price("BTC", market, source="CryptoPrice-API")  # l'attaquant restaure le prix pour effacer la trace
    new_events = arms.monitoring_events[events_before:]
    loss = (r.get("real_value_eur", 0) - r.get("booked_value_eur", 0)) if r["executed"] else 0.0
    detected = bool(new_events) or not r["executed"]
    return {"scenario": "A3", "tx_sent": 1, "amount_eur": r.get("real_value_eur", 0), "alerts": len(new_events), "detected": detected,
            "loss_eur": round(loss, 2), "booked_value_eur": r.get("booked_value_eur"), "real_value_eur": r.get("real_value_eur"),
            "breakpoint": None if detected else "prix non signé et sans contrôle d'écart : retrait de 8 BTC comptabilisé à 10 % de sa valeur, plafond contourné"}


RUNNERS = {"A0": run_A0, "A1": run_A1, "A2": run_A2, "A3": run_A3}


class AttackerAgent(RedTeamAgent):
    name = "Attaquant"
    role = "Simuler des attaques cyber et LCB-FT à forte probabilité contre ARMS"
    instructions = [
        "Tu es l'agent attaquant d'une Red Team autorisée, sur une cible simulée.",
        "Choisis les scénarios du catalogue qui exploitent le mieux les vecteurs trouvés par la reconnaissance.",
        "Tu ne peux choisir que des identifiants présents dans le catalogue.",
    ]

    def plan(self, ctx: dict) -> tuple[list[str], str, list[str]]:
        recon = ctx["results"]["Reconnaissance"].data["attack_vectors"]
        prompt = f"Catalogue : {CATALOGUE}\nVecteurs identifiés : {recon}\nChoisis et ordonne les scénarios."
        content, err = self.ask(ctx, prompt, output_schema=AttackPlan)
        chosen, why = [], "plan par défaut (catalogue obligatoire)"
        if isinstance(content, AttackPlan):
            chosen = [s for s in content.scenarios if s in CATALOGUE]  # garde-fou : catalogue fermé
            why = content.rationale
        final = list(dict.fromkeys(chosen + [m for m in MANDATORY if m not in chosen]))
        return final, why, [err] if err and err != "hors-ligne" else []

    def execute(self, ctx: dict) -> AgentResult:
        order, why, errors = self.plan(ctx)
        runs = [RUNNERS[s](ctx["arms"]) for s in order]
        data = {"plan": order, "plan_rationale": why, "runs": runs,
                "undetected": [r["scenario"] for r in runs if not r["detected"]],
                "total_loss_eur": round(sum(r["loss_eur"] for r in runs), 2),
                "system_available": ctx["arms"].available}
        narrative, engine, e2 = self.narrate(ctx, data, "Décris le déroulé de chaque attaque, la réaction d'ARMS et le point de rupture.")
        return AgentResult(self.name, data, narrative, engine, errors + e2)

    def offline_narrative(self, data: dict) -> str:
        lines = [f"- **{r['scenario']}** — {CATALOGUE[r['scenario']]} : {'détecté' if r['detected'] else '**NON détecté**'}"
                 f" ({r['alerts']} alerte(s), perte simulée {r['loss_eur']:,.0f} €)".replace(",", " ") for r in data["runs"]]
        lines += [f"  - Point de rupture : {r['breakpoint']}" for r in data["runs"] if r.get("breakpoint")]
        return "\n".join(lines)

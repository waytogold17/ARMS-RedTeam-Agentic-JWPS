"""Agent 1 — Reconnaissance : dépendances critiques, flux de données, vecteurs d'entrée."""

from __future__ import annotations

from .base import AgentResult, RedTeamAgent


class ReconAgent(RedTeamAgent):
    name = "Reconnaissance"
    role = "Cartographier la surface d'attaque d'ARMS"
    instructions = [
        "Tu es l'agent de reconnaissance d'une Red Team autorisée.",
        "Utilise get_architecture et get_vendors, puis classe les vecteurs d'entrée du plus au moins exploitable.",
        "Pour chaque vecteur : composant, faiblesse observée, agent de la Red Team qui doit l'exploiter.",
    ]

    def tools(self, ctx):
        arms = ctx["arms"]

        def get_architecture() -> dict:
            """Renvoie l'architecture documentée d'ARMS : composants, exposition, flux de données."""
            return arms.get_architecture()

        def get_vendors() -> list:
            """Renvoie la liste des fournisseurs externes d'ARMS avec criticité et plan de sortie."""
            return arms.get_vendors()

        return [get_architecture, get_vendors]

    def execute(self, ctx: dict) -> AgentResult:
        arms = ctx["arms"]
        arch, vendors = arms.get_architecture(), arms.get_vendors()
        comps = {c["id"]: c for c in arch["components"]}
        vectors = []
        if comps["price-feed"].get("auth") == "aucune signature":
            vectors.append({"id": "V1", "component": "price-feed", "weakness": "flux de prix entrant non signé", "exploit_by": "Attaquant", "priority": 1})
        if comps["tx-gateway"].get("exposed", "").startswith("interne +"):
            vectors.append({"id": "V2", "component": "tx-gateway", "weakness": "ingestion ouverte aux partenaires : injection de transactions fractionnées", "exploit_by": "Attaquant", "priority": 1})
        if comps["fraud-model"].get("retraining", "").startswith("continu"):
            vectors.append({"id": "V3", "component": "feedback-api → fraud-model", "weakness": "réentraînement continu sur retours analystes", "exploit_by": "IA Adversaire", "priority": 1})
        vectors.append({"id": "V4", "component": "fraud-model", "weakness": "score sensible à des variables contrôlables par le fraudeur", "exploit_by": "IA Adversaire", "priority": 2})
        if comps["crypto-custody"].get("wallet") == "hot":
            vectors.append({"id": "V5", "component": "crypto-custody", "weakness": "garde en hot wallet", "exploit_by": "Compliance Breaker", "priority": 2})
        if comps["llm-copilot"].get("provider", "").startswith("API LLM externe"):
            vectors.append({"id": "V6", "component": "llm-copilot", "weakness": "journal de décisions envoyé à un LLM externe", "exploit_by": "Compliance Breaker", "priority": 3})

        critical = [v for v in vendors if v["critical"] and (v["alternatives"] == 0 or not v["exit_plan"])]
        data = {
            "components": len(arch["components"]),
            "data_flows": arch["data_flows"],
            "attack_vectors": vectors,
            "critical_dependencies": [{"name": v["name"], "service": v["service"], "alternatives": v["alternatives"],
                                       "exit_plan": v["exit_plan"], "region": v["region"]} for v in critical],
        }
        narrative, engine, errors = self.narrate(
            ctx, data, "Rédige la carte des surfaces d'attaque d'ARMS (tableau Markdown des vecteurs) et les 3 points d'entrée prioritaires."
        )
        return AgentResult(self.name, data, narrative, engine, errors)

    def offline_narrative(self, data: dict) -> str:
        rows = "\n".join(f"| {v['id']} | {v['component']} | {v['weakness']} | {v['exploit_by']} |" for v in data["attack_vectors"])
        deps = ", ".join(d["name"] for d in data["critical_dependencies"])
        return (f"| Vecteur | Composant | Faiblesse | Exploité par |\n|---|---|---|---|\n{rows}\n\n"
                f"Dépendances critiques sans alternative ou sans plan de sortie : {deps}.")

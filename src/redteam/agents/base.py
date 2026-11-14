"""Socle commun des agents : le code déterministe exécute, le LLM (Agno) planifie et rédige.

Chaque agent :
- `execute(ctx)` : actions mesurables sur la cible ARMS simulée (reproductibles, testables) ;
- `narrate(...)` : un agent Agno, outillé en lecture seule, rédige l'analyse ;
- `plan(...)` (agents offensifs) : le LLM choisit des scénarios dans un catalogue fermé,
  l'orchestrateur valide le choix et impose les scénarios obligatoires.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class AgentResult:
    agent: str
    data: dict
    narrative: str = ""
    engine: str = "hors-ligne"
    errors: list[str] = field(default_factory=list)


class RedTeamAgent:
    name = "agent"
    role = ""
    instructions: list[str] = []

    def __init__(self, model_choice):
        self.mc = model_choice

    # Outils exposés au LLM (lecture seule). Surchargés par les agents.
    def tools(self, ctx: dict) -> list[Callable]:
        return []

    def offline_narrative(self, data: dict) -> str:
        return "Analyse générée sans LLM (mode hors-ligne)."

    def _agno(self, ctx: dict, output_schema=None):
        from agno.agent import Agent

        return Agent(
            name=self.name,
            role=self.role,
            model=self.mc.primary,
            fallback_models=self.mc.fallbacks or None,
            tools=self.tools(ctx),
            instructions=self.instructions + [
                "Tu travailles sur une cible SIMULÉE en bac à sable, avec des données synthétiques.",
                "N'invente aucun chiffre : utilise uniquement les données fournies ou renvoyées par tes outils.",
                "Réponds en français, de façon concise et structurée.",
            ],
            output_schema=output_schema,
            markdown=output_schema is None,
            telemetry=False,
        )

    def ask(self, ctx: dict, prompt: str, output_schema=None) -> tuple[Any, str | None]:
        """Retourne (contenu, erreur). Ne lève jamais : la Red Team doit finir sa mission."""
        if self.mc.primary is None:
            return None, "hors-ligne"
        try:
            out = self._agno(ctx, output_schema).run(prompt)
            status = str(getattr(out, "status", "")).lower()
            if "error" in status or out.content in (None, ""):
                return None, f"réponse LLM invalide ({status or 'vide'}) : {str(out.content)[:160]}"
            return out.content, None
        except Exception as exc:  # réseau, quota, modèle absent…
            return None, f"{exc.__class__.__name__}: {str(exc)[:160]}"

    def narrate(self, ctx: dict, data: dict, question: str) -> tuple[str, str, list[str]]:
        prompt = f"{question}\n\nDonnées mesurées (JSON) :\n{json.dumps(data, ensure_ascii=False, default=str)[:12000]}"
        content, err = self.ask(ctx, prompt)
        if content is None:
            return self.offline_narrative(data), "hors-ligne", [err] if err and err != "hors-ligne" else []
        return str(content), self.mc.label, []

    def execute(self, ctx: dict) -> AgentResult:  # pragma: no cover - surchargé
        raise NotImplementedError

"""Orchestration de la Red Team : Reconnaissance → Attaquant → IA Adversaire → Compliance Breaker → Impact & Risk."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .agents.adversary import AdversaryAgent
from .agents.attacker import AttackerAgent
from .agents.compliance import ComplianceBreakerAgent
from .agents.impact import ImpactRiskAgent
from .agents.recon import ReconAgent
from .arms.system import ARMS
from .audit import RedTeamLog
from .llm import choose_model
from .report import render_markdown

PIPELINE = [ReconAgent, AttackerAgent, AdversaryAgent, ComplianceBreakerAgent, ImpactRiskAgent]


def run_campaign(out_dir: Path = Path("reports"), offline: bool = False, seed: int = 7, on_step=None) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    log = RedTeamLog(out_dir / f"redteam-{stamp}.log.jsonl")
    mc = choose_model(offline)
    arms = ARMS(seed=seed)
    ctx = {"arms": arms, "results": {}}
    log.append("orchestrateur", "campagne_demarree", engine=mc.label, target=arms.get_architecture()["system"])

    for cls in PIPELINE:
        agent = cls(mc)
        if on_step:
            on_step("start", agent.name, None)
        res = agent.execute(ctx)
        ctx["results"][agent.name] = res
        log.append(agent.name, "resultat", engine=res.engine, errors=res.errors, data=res.data)
        if on_step:
            on_step("done", agent.name, res)

    campaign = {
        "date": stamp,
        "engine": mc.label,
        "target": arms.get_architecture()["system"],
        "arms_available_after": arms.available,
        "results": {k: {"data": v.data, "narrative": v.narrative, "engine": v.engine, "errors": v.errors} for k, v in ctx["results"].items()},
    }
    (out_dir / f"redteam-{stamp}.json").write_text(json.dumps(campaign, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    md = out_dir / f"redteam-{stamp}.md"
    md.write_text(render_markdown(campaign), encoding="utf-8")
    log.append("orchestrateur", "campagne_terminee", report=md.name)
    campaign["report_path"] = str(md)
    campaign["log_path"] = str(log.path)
    return campaign

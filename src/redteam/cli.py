"""CLI de la Red Team : `redteam run` lance la campagne complète, `redteam verify-log` contrôle le journal."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
ICONS = {"Reconnaissance": "🛰", "Attaquant": "⚔", "IA Adversaire": "🧠", "Compliance Breaker": "⚖", "Impact & Risk": "📊"}


def _on_step(phase, name, res):
    if phase == "start":
        console.rule(f"{ICONS.get(name, '•')}  Agent {name}")
        return
    console.print(Panel(res.narrative.strip()[:2500], title=f"{name} · moteur {res.engine}", border_style="cyan"))
    for e in res.errors:
        console.print(f"[yellow]⚠ LLM : {e} → repli hors-ligne[/yellow]")


def cmd_run(args) -> int:
    from .orchestrator import run_campaign

    console.print(Panel.fit("Red Team agentique — cible ARMS SIMULÉE (bac à sable, données synthétiques)", border_style="red"))
    c = run_campaign(Path(args.out), offline=args.offline, seed=args.seed, on_step=_on_step)
    imp = c["results"]["Impact & Risk"]["data"]
    t = Table(title=f"Score global {imp['global_risk_score']:.2f} — {imp['global_level']}")
    for col in ("#", "Vulnérabilité", "Exposition (€)", "Score", "Niveau"):
        t.add_column(col)
    for i, v in enumerate(imp["vulnerabilities"], 1):
        t.add_row(str(i), v["title"], f"{v['exposure_eur']:,.0f}".replace(",", " "), f"{v['risk_score']:.2f}", v["level"])
    console.print(t)
    console.print(f"Rapport : [bold]{c['report_path']}[/bold]\nJournal : {c['log_path']}")
    return 0


def cmd_verify(args) -> int:
    from .audit import RedTeamLog

    ok, n = RedTeamLog.verify(Path(args.path))
    console.print(f"Journal {'intègre' if ok else 'ALTÉRÉ'} ({n} entrées vérifiées)")
    return 0 if ok else 1

def _load_dotenv(path: Path = Path(".env")) -> None:
    """Charge .env sans écraser les variables déjà définies (clé jamais affichée)."""
    if not path.is_file():
        return
    import os
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if value.strip():
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

def main(argv=None) -> int:
    _load_dotenv()
    p = argparse.ArgumentParser(prog="redteam", description="Red Team agentique contre ARMS (simulation)")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="lancer la campagne complète (5 agents)")
    r.add_argument("--out", default="reports")
    r.add_argument("--offline", action="store_true", help="sans LLM (narration par modèles de texte)")
    r.add_argument("--seed", type=int, default=7)
    r.set_defaults(fn=cmd_run)
    v = sub.add_parser("verify-log", help="vérifier l'intégrité d'un journal de campagne")
    v.add_argument("path")
    v.set_defaults(fn=cmd_verify)
    args = p.parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())

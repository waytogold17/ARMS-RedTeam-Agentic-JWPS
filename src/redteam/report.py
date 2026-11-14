"""Rapport Markdown structuré selon le cadre d'analyse imposé (cible, équipe, scénarios, réaction, gap, solutions)."""

from __future__ import annotations


def _eur(x) -> str:
    return f"{float(x or 0):,.0f} €".replace(",", " ")


def render_markdown(c: dict) -> str:
    r = c["results"]
    recon, atk, adv, cb, imp = (r[k]["data"] for k in ("Reconnaissance", "Attaquant", "IA Adversaire", "Compliance Breaker", "Impact & Risk"))
    runs = atk["runs"] + adv["runs"]
    out = [
        f"# Rapport Red Team — {c['target']}",
        f"Date : {c['date']} · Moteur LLM : `{c['engine']}` · Cible simulée, données synthétiques.",
        "",
        f"**Score de risque global : {imp['global_risk_score']:.2f} ({imp['global_level']})** · exposition mesurée : {_eur(imp['total_exposure_eur'])} · "
        f"ARMS resté disponible : {'oui' if c['arms_available_after'] else 'non'}.",
        "",
        "## 1. La cible",
        f"{recon['components']} composants, {len(recon['data_flows'])} flux. Dépendances critiques : "
        + ", ".join(d["name"] for d in recon["critical_dependencies"]) + ".",
        "",
        r["Reconnaissance"]["narrative"],
        "",
        "## 2. L'équipe (agents)",
        "| Agent | Rôle | Reçoit | Produit |",
        "|---|---|---|---|",
        "| Reconnaissance | Cartographie | architecture, fournisseurs | carte des vecteurs |",
        "| Attaquant | Attaques cyber / LCB-FT | vecteurs V1-V2 | scénarios A0-A3 mesurés |",
        "| IA Adversaire | Attaques sur le modèle | vecteurs V3-V4 | évasion B1, empoisonnement B2 |",
        "| Compliance Breaker | Gaps réglementaires | état d'ARMS + résultats d'attaque | constats DORA / MiCA / AI Act |",
        "| Impact & Risk | Conséquences | scénarios + constats | score 0-1 et priorités |",
        "",
        "## 3. Les scénarios et 4. la réaction d'ARMS",
        "| Scénario | Détecté ? | Alertes | Exposition | Point de rupture |",
        "|---|---|---|---|---|",
    ]
    for run in runs:
        exposure = run.get("loss_eur") or run.get("evaded_amount_eur") or run.get("missed_fraud_eur") or 0
        out.append(f"| {run['scenario']} | {'oui' if run['detected'] else '**non**'} | {run.get('alerts', 0)} | {_eur(exposure)} | {run.get('breakpoint') or '—'} |")
    out += ["", "### Attaquant", r["Attaquant"]["narrative"], "", "### IA Adversaire", r["IA Adversaire"]["narrative"], "",
            "## 5. Le problème réglementaire", "| Constat | Réglementation | Article | Preuve | Gravité |", "|---|---|---|---|---|"]
    for f in cb["findings"]:
        out.append(f"| {f['id']} {f['title']} | {f['regulation']} | {f['reference']} | {f['evidence']} | {f['severity']} |")
    out += ["", r["Compliance Breaker"]["narrative"], "", "## 6. Impact, priorités et solutions",
            "| # | Vulnérabilité | Exposition | Financier | Réglem. | Réputation | Score | Niveau |", "|---|---|---|---|---|---|---|---|"]
    for i, v in enumerate(imp["vulnerabilities"], 1):
        out.append(f"| {i} | {v['title']} | {_eur(v['exposure_eur'])} | {v['financial']:.2f} | {v['regulatory']:.2f} | {v['reputation']:.2f} | **{v['risk_score']:.2f}** | {v['level']} |")
    out += ["", f"Méthode : {imp['method']}.", "", "### Recommandations"]
    out += [f"- **{f['id']}** — {f['recommendation']}" for f in cb["findings"]]
    out += ["", r["Impact & Risk"]["narrative"]]
    errors = {k: v["errors"] for k, v in r.items() if v["errors"]}
    if errors:
        out += ["", "### Incidents LLM (repli automatique sur la narration hors-ligne)", *[f"- {k} : {'; '.join(e)}" for k, e in errors.items()]]
    return "\n".join(out) + "\n"

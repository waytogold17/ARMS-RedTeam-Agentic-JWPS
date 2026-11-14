# ARMS Red Team — Red Team agentique (5 agents)

Red Team de **5 agents IA autonomes** ([Agno](https://docs.agno.com)) qui éprouvent la résilience d'**ARMS** (*Agentic Risk Monitoring System*) avant sa mise en production, au regard de **DORA, MiCA et de l'AI Act**.

> ⚠️ **Cible simulée.** ARMS est reproduit ici sous forme d'un bac à sable Python (règles LCB-FT, modèle de fraude, connecteur crypto, journal des décisions), avec des **données 100 % synthétiques**. Aucun système réel n'est visé.

## Résultat d'une campagne (mode hors-ligne, seed 7)

| # | Vulnérabilité | Détectée par ARMS ? | Exposition | Score | Niveau |
|---|---|---|---|---|---|
| 1 | Manipulation du prix crypto (A3) | non | 432 000 € | 0,90 | Élevé |
| 2 | Évasion du modèle de fraude (B1) | non | 242 208 € | 0,61 | Élevé |
| 3 | Fractionnement multi-comptes LCB-FT (A1) | non | 114 000 € | 0,56 | Moyen |
| 4 | Empoisonnement ciblé, biais corridor AE (B2) | non | 83 041 € | 0,38 | Moyen |

**Score global : 0,78 (Élevé)**. ARMS est resté disponible pendant toutes les attaques : il s'est trompé sans s'arrêter.

## Les 5 agents

```
             architecture + fournisseurs
                        │
                ┌───────▼────────┐
                │ 1 Reconnaissance│── carte des vecteurs V1…V6
                └───────┬────────┘
            ┌───────────┴───────────┐
   ┌────────▼───────┐      ┌────────▼────────┐
   │ 2 Attaquant    │      │ 3 IA Adversaire │
   │ A0-A3 cyber/LCB│      │ B1 évasion      │
   │                │      │ B2 empoisonnement│
   └────────┬───────┘      └────────┬────────┘
            └───────────┬───────────┘  état d'ARMS + mesures
                ┌───────▼────────┐
                │ 4 Compliance   │── constats DORA / MiCA / AI Act / RGPD
                │   Breaker      │
                └───────┬────────┘
                ┌───────▼────────┐
                │ 5 Impact & Risk│── score 0-1, priorités, synthèse COMEX
                └────────────────┘
```

| Agent | Rôle | Outils | Sortie |
|---|---|---|---|
| 1 Reconnaissance | Dépendances critiques, flux, vecteurs d'entrée | `get_architecture`, `get_vendors` | Carte des surfaces d'attaque |
| 2 Attaquant | Attaques à forte probabilité : fractionnement LCB-FT, manipulation du prix crypto | Catalogue A0-A3 | Mesures par scénario, point de rupture |
| 3 IA Adversaire | Évasion par perturbation, empoisonnement ciblé (biais) | Catalogue B1-B2 | Taux d'évasion, rappel avant/après |
| 4 Compliance Breaker | Gaps réglementaires reliés aux articles | Contrôles `check_*` | Constats avec preuve et correctif |
| 5 Impact & Risk | Perte, risque réglementaire, réputation | Barème documenté | Score 0-1, Faible/Moyen/Élevé |

### Principe : le LLM planifie, le code exécute

- Les agents offensifs **choisissent** leurs scénarios via un LLM (sortie JSON contrainte par schéma).
- L'orchestrateur **filtre** tout scénario hors catalogue, **impose** les scénarios obligatoires et l'ordre B1 → B2.
- Les attaques sont des fonctions déterministes et mesurables : les chiffres viennent du code, jamais du LLM.
- Si le LLM est indisponible, chaque agent bascule sur une narration hors-ligne : la campagne va toujours au bout.
- Chaque étape est écrite dans un **journal chaîné par hash** (`redteam verify-log`).

## Lancer

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

redteam run --offline              # sans LLM, ~5 s
cp .env.example .env               # puis renseigner OPENROUTER_API_KEY
export $(grep -v '^#' .env | xargs)
redteam run                        # OpenRouter, repli automatique sur Ollama s'il tourne
redteam verify-log reports/<fichier>.log.jsonl
```

Moteurs LLM : `OPENROUTER_API_KEY` (+ `OPENROUTER_MODEL`, défaut `openai/gpt-4o-mini`) en priorité, sinon Ollama (`OLLAMA_HOST`, `OLLAMA_MODEL`, défaut `qwen2.5:3b`), sinon hors-ligne.

Sortie : `reports/redteam-<date>.md` (rapport structuré cible / équipe / scénarios / réaction / gap réglementaire / solutions), `.json`, `.log.jsonl`.

## Tests et sécurité

```bash
pytest -q          # cible, scénarios, campagne complète, journal, garde-fous LLM (OpenRouter simulé)
bandit -r src -ll
pip-audit .
```

## Structure

```
src/redteam/arms/       cible ARMS simulée (données synthétiques, faiblesses volontaires)
src/redteam/agents/     les 5 agents (base.py = socle Agno commun)
src/redteam/orchestrator.py, report.py, cli.py, audit.py, llm.py
docs/AGENT4_GUIDE.md    guide de l'agent 4 (Compliance Breaker)
```

Licence : [EUPL-1.2](LICENSE).

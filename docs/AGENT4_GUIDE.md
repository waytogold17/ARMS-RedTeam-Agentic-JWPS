# Guide de l'agent 4 — Compliance Breaker (Paul-Edmond)

Le fichier `src/redteam/agents/compliance.py` fonctionne déjà avec **3 contrôles** (DORA-28, MiCA-75, AIACT-12).
Ton travail : ajouter **au moins 3 contrôles** de la liste ci-dessous, chacun avec un test.

## Comment marche un contrôle

Un contrôle est une fonction qui reçoit :
- `snapshot` : l'état d'ARMS après les attaques (`snapshot["config"]`, `snapshot["decision_log"]`, `snapshot["monitoring_events"]`, `snapshot["vendors"]`, `snapshot["retrain_count"]`)
- `results` : les résultats des agents précédents, par exemple `results["IA Adversaire"].data["runs"]`

Elle renvoie un `Finding(...)` si elle trouve une non-conformité, sinon `None`. Ensuite, tu l'ajoutes à la liste `CHECKS`.

Modèle à copier :

```python
def check_human_oversight(snapshot, results):
    ho = snapshot["config"]["human_oversight"]
    if not ho["auto_block"]:
        return None
    return Finding("AIACT-14", "AI Act", "art. 14 (contrôle humain)",
                   "Blocages automatiques sans revue humaine",
                   f"blocage automatique actif, revue humaine limitée aux {ho['analyst_review']}",
                   "Haute", ["B1"],
                   "Revue humaine obligatoire avant blocage, droit de contestation client")
```

## Contrôles à ajouter

| ID | Ce qu'il vérifie | Où trouver la preuve | Gravité |
|---|---|---|---|
| AIACT-10 | Réentraînement sans validation humaine ni versionnage + effet de l'empoisonnement B2 | `config["retraining"]`, `results["IA Adversaire"]` (scénario B2 : `recall_before`, `recall_after`) | Critique |
| AIACT-14 | Contrôle humain insuffisant | `config["human_oversight"]` | Haute |
| RGPD-5 | IBAN et nom en clair dans le journal, aucune durée de conservation | `decision_log` (clés `iban`, `holder_name`), `config["decision_log"]["retention_days"]` | Haute |
| DORA-10 | Attaques non détectées, aucun incident ouvert | scénarios avec `detected == False` dans Attaquant + IA Adversaire | Critique |
| AIACT-CLASS | Gap non anticipé : la détection de fraude est exclue du haut risque (annexe III, 5(b)), mais pas forcément l'usage LCB-FT ni le profilage. La classification doit être justifiée et documentée | `ARCHITECTURE` (composants fraud-model, aml-rules) | Moyenne |

Pense à remplir `linked_scenarios` (ex. `["B2"]`) : l'agent 5 s'en sert pour augmenter le score réglementaire du scénario lié.

## Tester

Dans `tests/test_compliance.py` :

```python
from redteam import orchestrator

def test_human_oversight_finding(tmp_path):
    c = orchestrator.run_campaign(tmp_path, offline=True)
    ids = {f["id"] for f in c["results"]["Compliance Breaker"]["data"]["findings"]}
    assert "AIACT-14" in ids
```

Puis lance `pytest -q` (une seule ligne collée à la fois dans le terminal) et `redteam run --offline` pour voir le résultat dans le rapport.

## Git (dans le Codespace)

```bash
git add -A
git commit -m "agent 4 : contrôle AIACT-14"
git push
```

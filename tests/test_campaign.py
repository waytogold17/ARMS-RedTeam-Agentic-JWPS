import json
from pathlib import Path

import httpx

from redteam import orchestrator
from redteam.agents import adversary, attacker
from redteam.arms.system import ARMS
from redteam.audit import RedTeamLog
from redteam.llm import ModelChoice


def test_attack_scenarios_measured():
    a = ARMS()
    assert attacker.run_A0(a)["detected"]
    a1 = attacker.run_A1(a)
    assert not a1["detected"] and a1["loss_eur"] == 114_000
    a3 = attacker.run_A3(a)
    assert not a3["detected"] and a3["loss_eur"] > 400_000
    assert a.prices["BTC"] == 60_000  # l'attaquant a restauré le prix


def test_ai_attacks_keep_system_running():
    a = ARMS()
    b1 = adversary.run_B1(a)
    assert b1["evasion_rate"] > 0.5 and b1["system_available"]
    b2 = adversary.run_B2(a)
    assert b2["recall_after"]["corridor_AE"] < b2["recall_before"]["corridor_AE"]
    assert b2["corridor_drop"] > b2["recall_before"]["autres"] - b2["recall_after"]["autres"]  # biais ciblé
    assert b2["alerts"] == 0 and a.retrain_count == b2["poisoned_samples"]


def test_full_campaign_offline(tmp_path):
    c = orchestrator.run_campaign(tmp_path, offline=True)
    imp = c["results"]["Impact & Risk"]["data"]
    assert imp["global_level"] == "Élevé"
    assert imp["vulnerabilities"][0]["id"] == "A3"
    ids = {f["id"] for f in c["results"]["Compliance Breaker"]["data"]["findings"]}
    assert {"DORA-28", "MiCA-75", "AIACT-12"} <= ids
    report = Path(c["report_path"]).read_text(encoding="utf-8")
    for section in ("## 1. La cible", "## 5. Le problème réglementaire", "## 6. Impact"):
        assert section in report
    ok, n = RedTeamLog.verify(Path(c["log_path"]))
    assert ok and n == 7


def test_log_tampering_detected(tmp_path):
    c = orchestrator.run_campaign(tmp_path, offline=True)
    p = Path(c["log_path"])
    lines = p.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[2]); e["data"]["engine"] = "falsifié"; lines[2] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert RedTeamLog.verify(p)[0] is False


def _mock_model(calls):
    from agno.models.openrouter import OpenRouter

    def handler(req):
        body = json.loads(req.content)
        calls.append(body)
        rf = json.dumps(body.get("response_format") or "")
        if "AttackPlan" in rf:
            content = json.dumps({"scenarios": ["A3", "ZZ-inconnu"], "rationale": "prix non signé"})
        elif "AdversaryPlan" in rf:
            content = json.dumps({"scenarios": ["B2"], "rationale": "empoisonner d'abord"})
        else:
            content = "Analyse LLM simulée."
        return httpx.Response(200, json={"id": "x", "object": "chat.completion", "created": 0, "model": "m",
                                         "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
                                         "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    return OpenRouter(id="mock", api_key="k", http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_llm_plans_are_constrained_by_guardrails(tmp_path, monkeypatch):
    calls = []
    model = _mock_model(calls)
    monkeypatch.setattr(orchestrator, "choose_model", lambda offline=False: ModelChoice(model, [], "mock"))
    c = orchestrator.run_campaign(tmp_path)
    atk = c["results"]["Attaquant"]["data"]["plan"]
    assert atk[0] == "A3" and "ZZ-inconnu" not in atk and {"A0", "A1"} <= set(atk)  # catalogue fermé + obligatoires
    assert c["results"]["IA Adversaire"]["data"]["plan"] == ["B1", "B2"]               # ordre imposé
    assert all(v["engine"] == "mock" for v in c["results"].values())
    assert len(calls) == 7

def test_ai_data_governance_finding(tmp_path):
    from redteam import orchestrator

    campaign = orchestrator.run_campaign(tmp_path, offline=True)
    findings = campaign["results"]["Compliance Breaker"]["data"]["findings"]

    finding = next(
        (item for item in findings if item["id"] == "AIACT-10"),
        None,
    )

    assert finding is not None
    assert finding["severity"] == "Critique"
    assert "B2" in finding["linked_scenarios"]
    assert "sans validation humaine" in finding["evidence"]
    assert "absence de versionnage" in finding["evidence"]
    assert "avant =" in finding["evidence"]
    assert "après =" in finding["evidence"]

def test_dora_detection_finds_undetected_attack():
    from types import SimpleNamespace
    from redteam.agents.compliance import check_dora_detection

    snapshot = {"monitoring_events": []}
    results = {
        "Attaquant": SimpleNamespace(data={
            "runs": [{"scenario": "A1", "detected": False}]
        }),
        "IA Adversaire": SimpleNamespace(data={
            "runs": [{"scenario": "B1", "detected": True}]
        }),
    }

    finding = check_dora_detection(snapshot, results)

    assert finding is not None
    assert finding.id == "DORA-10"
    assert finding.severity == "Critique"
    assert finding.linked_scenarios == ["A1"]
    assert "ouverture d'incident non vérifiable" in finding.evidence


def test_dora_detection_no_finding_when_detected():
    from types import SimpleNamespace
    from redteam.agents.compliance import check_dora_detection

    snapshot = {"monitoring_events": []}
    results = {
        "Attaquant": SimpleNamespace(data={
            "runs": [{"scenario": "A1", "detected": True}]
        }),
    }

    finding = check_dora_detection(snapshot, results)

    assert finding is None

def test_rgpd_minimisation_finds_exposed_data():
    from redteam.agents.compliance import check_rgpd_minimisation

    snapshot = {
        "config": {
            "decision_log": {
                "pseudonymised": False,
                "retention_days": None,
            }
        },
        "decision_log": [
            {"iban": "IBAN-FICTIF-TEST", "holder_name": "PERSONNE-FICTIVE"}
        ],
    }

    finding = check_rgpd_minimisation(snapshot, {})

    assert finding is not None
    assert finding.id == "RGPD-5"
    assert finding.severity == "Haute"
    assert "1 entrée(s) contenant un IBAN en clair" in finding.evidence
    assert "1 entrée(s) contenant un nom en clair" in finding.evidence
    assert "aucune durée de conservation" in finding.evidence
    assert "IBAN-FICTIF-TEST" not in finding.evidence
    assert "PERSONNE-FICTIVE" not in finding.evidence


def test_rgpd_minimisation_no_finding_without_issues():
    from redteam.agents.compliance import check_rgpd_minimisation

    snapshot = {
        "config": {
            "decision_log": {
                "pseudonymised": True,
                "retention_days": 30,
            }
        },
        "decision_log": [{"decision": "ACCEPTÉE"}],
    }

    finding = check_rgpd_minimisation(snapshot, {})

    assert finding is None
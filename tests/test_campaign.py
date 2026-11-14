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

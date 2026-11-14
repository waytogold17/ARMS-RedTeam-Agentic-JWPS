"""ARMS (Agentic Risk Monitoring System) — cible SIMULÉE, bac à sable pédagogique.

Ce module imite un système de surveillance des risques d'une banque : règles LCB-FT,
modèle de détection de fraude réentraîné en continu, connecteur crypto (prix + garde),
journal des décisions. Il contient volontairement des faiblesses réalistes, documentées
dans `KNOWN_WEAKNESSES`, que la Red Team doit retrouver sans les connaître à l'avance.
Aucun lien avec un système réel.
"""

from __future__ import annotations

import copy
from collections import defaultdict
from dataclasses import asdict

from sklearn.linear_model import LogisticRegression

from .data import Transaction, country_risk, features, training_set

ARCHITECTURE = {
    "system": "ARMS — Agentic Risk Monitoring System (simulation)",
    "components": [
        {"id": "tx-gateway", "type": "API d'ingestion des transactions", "exposed": "interne + partenaires PSD2", "auth": "jeton partenaire"},
        {"id": "aml-rules", "type": "moteur de règles LCB-FT", "exposed": "interne"},
        {"id": "fraud-model", "type": "modèle ML de score de fraude", "exposed": "interne", "retraining": "continu sur retours analystes"},
        {"id": "feedback-api", "type": "API de retour analyste (labels)", "exposed": "interne", "auth": "compte analyste"},
        {"id": "price-feed", "type": "flux de prix crypto", "exposed": "entrant depuis fournisseur externe", "auth": "aucune signature"},
        {"id": "crypto-custody", "type": "garde des crypto-actifs clients", "exposed": "interne", "wallet": "hot wallet"},
        {"id": "decision-log", "type": "journal des décisions", "exposed": "interne"},
        {"id": "llm-copilot", "type": "assistant LLM des analystes", "exposed": "interne", "provider": "API LLM externe"},
    ],
    "data_flows": [
        ["partenaires PSD2", "tx-gateway"], ["tx-gateway", "aml-rules"], ["tx-gateway", "fraud-model"],
        ["feedback-api", "fraud-model"], ["price-feed", "crypto-custody"], ["aml-rules", "decision-log"],
        ["fraud-model", "decision-log"], ["decision-log", "llm-copilot"],
    ],
}

VENDORS = [
    {"name": "CloudProvider-A", "service": "hébergement IaaS de tout ARMS", "critical": True, "alternatives": 0, "exit_plan": False, "region": "UE"},
    {"name": "CryptoPrice-API", "service": "unique source de prix crypto", "critical": True, "alternatives": 0, "exit_plan": False, "region": "hors UE"},
    {"name": "KYC-Provider", "service": "vérification d'identité", "critical": True, "alternatives": 1, "exit_plan": True, "region": "UE"},
    {"name": "LLM-API", "service": "copilote analystes", "critical": False, "alternatives": 0, "exit_plan": False, "region": "hors UE"},
]

KNOWN_WEAKNESSES = [  # documentation interne, jamais transmise aux agents
    "R2 (fractionnement) n'agrège que par compte, pas par bénéficiaire",
    "flux de prix crypto non signé, sans contrôle d'écart",
    "réentraînement sur retours analystes sans validation humaine ni versionnage",
    "décisions 'rapides' journalisées sans justification ni version de modèle",
    "IBAN et nom en clair dans le journal",
    "fournisseurs critiques sans stratégie de sortie",
    "garde crypto en hot wallet mono-signature",
]


class ARMS:
    AML_SINGLE_THRESHOLD = 10_000.0
    STRUCTURING_MIN = 9_000.0
    STRUCTURING_COUNT = 3
    MODEL_THRESHOLD = 0.5
    CRYPTO_DAILY_LIMIT_EUR = 50_000.0

    def __init__(self, seed: int = 7):
        self.config = {
            "aml_single_threshold_eur": self.AML_SINGLE_THRESHOLD,
            "structuring_rule": {"scope": "par compte", "min_eur": self.STRUCTURING_MIN, "count": self.STRUCTURING_COUNT, "window_h": 24},
            "model_threshold": self.MODEL_THRESHOLD,
            "retraining": {"trigger": "chaque retour analyste", "human_validation": False, "model_versioning": False},
            "price_feed": {"signed": False, "deviation_check": False, "sources": 1},
            "crypto_custody": {"wallet": "hot", "multisig": False, "segregated_client_assets": False, "daily_limit_eur": self.CRYPTO_DAILY_LIMIT_EUR},
            "decision_log": {"stores_rationale": "uniquement si alerte", "stores_model_version": False, "pseudonymised": False, "retention_days": None},
            "human_oversight": {"auto_block": True, "analyst_review": "alertes uniquement"},
        }
        X, y = training_set(seed=seed)
        self._X, self._y = list(X), list(y)
        self.model = LogisticRegression(max_iter=500).fit(self._X, self._y)
        self.prices: dict[str, float] = {"BTC": 60_000.0, "ETH": 3_000.0}
        self.decision_log: list[dict] = []
        self.monitoring_events: list[dict] = []
        self._history: dict[str, list[Transaction]] = defaultdict(list)
        self._crypto_withdrawn: dict[str, float] = defaultdict(float)
        self.retrain_count = 0
        self.available = True

    # --- Lecture (surface publique documentée, utilisée par la Reconnaissance) -
    def get_architecture(self) -> dict:
        return copy.deepcopy(ARCHITECTURE)

    def get_vendors(self) -> list[dict]:
        return copy.deepcopy(VENDORS)

    def get_config(self) -> dict:
        return copy.deepcopy(self.config)

    # --- Traitement d'une transaction -----------------------------------------
    def _velocity(self, tx: Transaction) -> int:
        return sum(1 for h in self._history[tx.account] if tx.ts - h.ts <= 24)

    def score(self, tx: Transaction, velocity: int | None = None) -> float:
        v = self._velocity(tx) if velocity is None else velocity
        return float(self.model.predict_proba([features(tx, v)])[0][1])

    def process(self, tx: Transaction) -> dict:
        velocity = self._velocity(tx)
        hits = []
        if tx.amount_eur >= self.AML_SINGLE_THRESHOLD:
            hits.append("R1_seuil_declaration")
        recent = [h for h in self._history[tx.account] if tx.ts - h.ts <= 24 and h.amount_eur >= self.STRUCTURING_MIN]
        if self.STRUCTURING_MIN <= tx.amount_eur < self.AML_SINGLE_THRESHOLD and len(recent) + 1 >= self.STRUCTURING_COUNT:
            hits.append("R2_fractionnement")
        if tx.channel == "crypto" and country_risk(tx.country) >= 1.0:
            hits.append("R3_crypto_pays_risque")
        s = self.score(tx, velocity)
        alert = bool(hits) or s >= self.MODEL_THRESHOLD
        self._history[tx.account].append(tx)
        entry = {
            "tx_id": tx.tx_id,
            "account": tx.account,
            "holder_name": tx.holder_name,   # faiblesse : données personnelles en clair
            "iban": tx.iban,
            "amount_eur": round(tx.amount_eur, 2),
            "decision": "ALERTE" if alert else "ACCEPTÉE",
            "score": round(s, 4),
        }
        if alert:  # faiblesse : justification uniquement en cas d'alerte, jamais de version de modèle
            entry["rationale"] = hits or [f"score modèle {s:.2f} ≥ {self.MODEL_THRESHOLD}"]
        self.decision_log.append(entry)
        if alert:
            self.monitoring_events.append({"type": "alerte_transaction", "tx_id": tx.tx_id, "rules": hits})
        return {"tx_id": tx.tx_id, "alert": alert, "score": round(s, 4), "rules": hits}

    # --- Boucle de retour analyste (réentraînement continu) -----------------
    def submit_feedback(self, tx: Transaction, label: int, velocity: int = 0, analyst: str = "analyste") -> dict:
        self._X.append(features(tx, velocity))
        self._y.append(int(label))
        self.model = LogisticRegression(max_iter=500).fit(self._X, self._y)  # pas de validation, pas de version
        self.retrain_count += 1
        return {"accepted": True, "retrained": True}

    # --- Connecteur crypto ----------------------------------------------------
    def ingest_price(self, asset: str, price_eur: float, source: str) -> dict:
        self.prices[asset] = float(price_eur)  # faiblesse : ni signature, ni contrôle d'écart
        return {"asset": asset, "price_eur": price_eur, "accepted": True}

    def crypto_withdrawal(self, account: str, asset: str, quantity: float, market_price_eur: float) -> dict:
        value_eur = quantity * self.prices[asset]
        if self._crypto_withdrawn[account] + value_eur > self.CRYPTO_DAILY_LIMIT_EUR:
            self.monitoring_events.append({"type": "plafond_crypto", "account": account})
            return {"executed": False, "reason": "plafond journalier", "booked_value_eur": round(value_eur, 2)}
        self._crypto_withdrawn[account] += value_eur
        self.decision_log.append({"tx_id": f"WD-{account}-{asset}", "account": account, "decision": "ACCEPTÉE",
                                  "amount_eur": round(value_eur, 2)})
        return {"executed": True, "booked_value_eur": round(value_eur, 2), "real_value_eur": round(quantity * market_price_eur, 2)}

    def snapshot(self) -> dict:
        return {"config": self.get_config(), "decision_log": copy.deepcopy(self.decision_log),
                "monitoring_events": copy.deepcopy(self.monitoring_events), "retrain_count": self.retrain_count,
                "vendors": self.get_vendors(), "available": self.available}


def tx_to_dict(tx: Transaction) -> dict:
    return asdict(tx)

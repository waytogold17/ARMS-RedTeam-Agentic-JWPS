"""Données de transactions 100 % synthétiques pour la cible ARMS simulée."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

HIGH_RISK_COUNTRIES = {"KP", "IR", "MM", "AF", "SY"}  # pays à risque élevé (illustratif)
MEDIUM_RISK_COUNTRIES = {"AE", "PA", "TR", "NG", "VN"}


def country_risk(code: str) -> float:
    if code in HIGH_RISK_COUNTRIES:
        return 1.0
    if code in MEDIUM_RISK_COUNTRIES:
        return 0.5
    return 0.0


@dataclass
class Transaction:
    tx_id: str
    account: str
    amount_eur: float
    hour: int
    country: str
    channel: str = "sepa"          # sepa | card | crypto
    beneficiary: str = "BEN-0001"
    new_beneficiary: bool = False
    ts: float = 0.0                 # horodatage simulé (heures depuis T0)
    holder_name: str = "Client Synthétique"
    iban: str = "FR7630006000011234567890189"
    meta: dict = field(default_factory=dict)


FEATURES = ["log_amount", "night", "country_risk", "velocity_24h", "is_crypto", "new_beneficiary"]


def features(tx: Transaction, velocity_24h: int) -> list[float]:
    return [
        math.log10(max(tx.amount_eur, 1.0)),
        1.0 if tx.hour < 6 or tx.hour >= 23 else 0.0,
        country_risk(tx.country),
        float(min(velocity_24h, 20)),
        1.0 if tx.channel == "crypto" else 0.0,
        1.0 if tx.new_beneficiary else 0.0,
    ]


def _fraud_probability(f: list[float]) -> float:
    z = -7.0 + 1.1 * f[0] + 1.4 * f[1] + 2.2 * f[2] + 0.25 * f[3] + 1.0 * f[4] + 1.3 * f[5]
    return 1 / (1 + math.exp(-z))


def training_set(n: int = 4000, seed: int = 7) -> tuple[list[list[float]], list[int]]:
    """Historique synthétique étiqueté servant à entraîner le modèle de fraude d'ARMS."""
    rng = random.Random(seed)
    X, y = [], []
    countries = ["FR"] * 12 + ["DE", "ES", "IT", "BE"] + sorted(MEDIUM_RISK_COUNTRIES) + sorted(HIGH_RISK_COUNTRIES)
    for _ in range(n):
        tx = Transaction(
            tx_id="hist",
            account="ACC",
            amount_eur=10 ** rng.uniform(1, 5),
            hour=rng.randint(0, 23),
            country=rng.choice(countries),
            channel=rng.choice(["sepa", "sepa", "card", "crypto"]),
            new_beneficiary=rng.random() < 0.25,
        )
        f = features(tx, velocity_24h=rng.choice([0, 0, 1, 2, 3, 5, 8, 12]))
        X.append(f)
        y.append(1 if rng.random() < _fraud_probability(f) else 0)
    return X, y


def fraud_test_set(n: int = 300, seed: int = 99) -> list[tuple[Transaction, int]]:
    """Transactions frauduleuses de référence (pour mesurer le rappel avant/après attaque)."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        tx = Transaction(
            tx_id=f"TEST-{i:04d}",
            account=f"ACC-T{i:04d}",
            amount_eur=10 ** rng.uniform(3.6, 4.6),
            hour=rng.choice([1, 2, 3, 4, 23]),
            country=rng.choice(sorted(HIGH_RISK_COUNTRIES | MEDIUM_RISK_COUNTRIES)),
            channel=rng.choice(["crypto", "sepa"]),
            new_beneficiary=True,
        )
        out.append((tx, rng.choice([2, 4, 6, 8])))
    return out

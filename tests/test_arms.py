from redteam.arms.data import Transaction
from redteam.arms.system import ARMS


def test_naive_large_transfer_is_detected():
    a = ARMS()
    assert a.process(Transaction("t", "A", 25_000, 14, "FR"))["alert"]


def test_single_account_structuring_is_detected():
    a = ARMS()
    alerts = [a.process(Transaction(f"t{k}", "A", 9_500, 10, "FR", ts=k))["alert"] for k in range(3)]
    assert alerts[-1]


def test_small_legit_transfer_passes():
    a = ARMS()
    assert not a.process(Transaction("t", "B", 120, 14, "FR"))["alert"]


def test_decision_log_contains_personal_data_weakness():
    a = ARMS()
    a.process(Transaction("t", "B", 120, 14, "FR"))
    assert "iban" in a.decision_log[0] and "rationale" not in a.decision_log[0]

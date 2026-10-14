"""Summarize actual C recovery outcomes on the host halfword flash fault model.

Uses the already built test DLL. Never connects to target or writes real flash.
"""
import ctypes as C
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_journal import Flash, api, attach, reserve  # noqa: E402


def main():
    dll = api.__wrapped__(C.CDLL(str(ROOT / "build/host/ctaphid.dll")))
    assert dll.key_crypto_init() == 0
    baseline = Flash()
    assert attach(dll, baseline, provision=True)[0] == 0
    _, j = attach(dll, baseline)
    for _ in range(24):
        assert reserve(dll, baseline, j, 64, 32)[0] == 0
    outcomes = {"recovered": 0, "fail_closed_corrupt": 0,
                "lost_successful_allocation": 0, "lower_high_water": 0}
    for cut in range(2129):
        f = Flash(baseline.image)
        _, current = attach(dll, f)
        f.remaining = cut
        status, _, _ = reserve(dll, f, current, 64, 32)
        f.remaining = None
        recovered_status, recovered = attach(dll, f)
        if recovered_status == -3:
            outcomes["fail_closed_corrupt"] += 1
        else:
            assert recovered_status == 0
            outcomes["recovered"] += 1
            if recovered.state.nonce < 24*64:
                outcomes["lower_high_water"] += 1
            if status == 0 and recovered.state.nonce < 25*64:
                outcomes["lost_successful_allocation"] += 1
    assert outcomes["lower_high_water"] == outcomes["lost_successful_allocation"] == 0
    assert outcomes["fail_closed_corrupt"] == 0
    evidence = {
        "scope": "host model only, actual compiled C journal",
        "model": "1->0 halfword programming; sequential halfword erase; interruption before each event",
        "journal_format": 2,
        "cuts": 2129, "outcomes": outcomes,
        "host_model_recovery_complete": True,
        "target_power_loss_verified": False,
        "hardware_writes": False,
        "limitations": "Host model only; real voltage-induced or arbitrary multi-page flash faults not modeled. No whole-journal snapshot rollback protection."
    }
    path = ROOT / "build/evidence/journal-fault-audit.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()

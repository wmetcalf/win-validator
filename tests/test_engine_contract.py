"""The authenticode engine's output matches its contract (blastbox-engine.toml).

The engine code runs for real: AuthenticodeEngine.detonate() and HostRunner.validate_to_dir(),
which seals through blastbox's own run_detonation. Only the Windows VM is replaced: the pool's
``validate()`` replays verdicts myatg actually printed (tests/fixtures/myatg/, copied from the
myatg README's worked examples, plus the ErrJson skeleton myatg.cs formats for a refused input).

The checker ships on an unreleased blastbox branch, so this module skips on a released one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ec = pytest.importorskip("blastbox.contract.engine_contract")

from blastbox.limits import Limits  # noqa: E402

from winval_blastbox import engine as eng  # noqa: E402
from winval_blastbox.host_runner import HostRunner  # noqa: E402

CONTRACT_PATH = ec.find_contract(__file__)
CONTRACT = ec.load_contract(CONTRACT_PATH)
FIXTURES = sorted((Path(__file__).parent / "fixtures" / "myatg").glob("*.json"))
CODES = {d.code for d in CONTRACT.detections}


class _ReplayPool:
    """Stands in for WarmVmPool: answers validate() with a verdict myatg printed."""

    def __init__(self, verdict: dict | None = None, error: Exception | None = None) -> None:
        self.verdict, self.error = verdict, error

    def validate(self, path: str, params=None) -> dict:
        if self.error is not None:
            raise self.error
        return json.loads(json.dumps(self.verdict))


@pytest.fixture
def replay(monkeypatch):
    def use(pool: _ReplayPool) -> None:
        monkeypatch.setattr(eng, "get_pool", lambda stop_event=None: pool)
    return use


def _sample(tmp_path: Path, name: str = "sample.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(b"MZ" + b"\0" * 62)
    return p


def test_contract_validates_and_names_this_engine():
    assert CONTRACT_PATH is not None and CONTRACT_PATH.name == "blastbox-engine.toml"
    assert ec.main(["validate", str(CONTRACT_PATH)]) == 0
    assert CONTRACT.engine.name == eng.AuthenticodeEngine.name
    assert set(CONTRACT.engine.formats) == set(eng.AuthenticodeEngine.formats)


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.stem)
def test_detonate_result_conforms(tmp_path, replay, fixture):
    verdict = json.loads(fixture.read_text())
    replay(_ReplayPool(verdict))
    out = tmp_path / "out"
    out.mkdir()
    result = eng.AuthenticodeEngine().detonate(_sample(tmp_path), out, Limits())
    ec.assert_conforms(CONTRACT, result, out)
    # Every status myatg printed is one the contract names as a detection code, and a
    # graveyard hit carries the warning the contract lists.
    assert f"authenticode.status.{result.payload.fields['status']}" in CODES
    if (verdict.get("graveyard") or {}).get("hit"):
        assert "graveyard_hit" in {w.code for w in result.warnings}


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.stem)
def test_sealed_envelope_conforms(tmp_path, replay, fixture):
    replay(_ReplayPool(json.loads(fixture.read_text())))
    env = HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out")
    assert env["status"] == "ok"
    ec.assert_conforms(CONTRACT, env)


def test_vm_failure_seals_a_conforming_engine_error(tmp_path, replay):
    replay(_ReplayPool(error=RuntimeError("agent unreachable")))
    env = HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out")
    assert env["status"] == "engine_error"
    ec.assert_conforms(CONTRACT, env)


@pytest.mark.parametrize("rc", ["unknown", "none"])
def test_valid_with_unchecked_revocation_conforms_and_is_named(tmp_path, replay, rc):
    """myatg's Valid with revocation never checked reaches consumers as a contract-named status of its own."""
    verdict = json.loads((Path(__file__).parent / "fixtures" / "myatg" / "valid_script_graveyard_hit.json").read_text())
    verdict["chain"]["revocation_checked"] = rc
    replay(_ReplayPool(verdict))
    out = tmp_path / "out"
    out.mkdir()
    result = eng.AuthenticodeEngine().detonate(_sample(tmp_path), out, Limits())
    ec.assert_conforms(CONTRACT, result, out)
    assert result.payload.fields["status"] == "ValidRevocationUnchecked"
    assert "authenticode.status.ValidRevocationUnchecked" in CODES
    assert "authenticode.revocation.unchecked" in CODES
    assert "revocation-unknown-is-valid" not in {g.id for g in CONTRACT.gaps}


def test_rejected_job_param_seals_a_conforming_rejection(tmp_path, replay):
    replay(_ReplayPool(json.loads(FIXTURES[0].read_text())))
    env = HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out", params={"AUTHENTICODE_REV": "cached"})
    assert env["status"] == "rejected"
    ec.assert_conforms(CONTRACT, env)


def test_every_warning_code_the_engine_emits_is_named_by_the_contract():
    toml = CONTRACT_PATH.read_text()
    for code in ("graveyard_hit", "status_unrecognized", "param_unknown_value", "param_not_forwarded"):
        assert code in toml

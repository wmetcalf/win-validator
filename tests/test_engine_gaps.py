"""The engine closes the gaps its contract used to record.

* schema_version: the Record names the field set it carries.
* status vocabulary: a status myatg prints that the engine does not know is SAID (a warning).
* RDP verdicts: the RDP-only findings are indexed fields, and file_sha256 is the input's hash.
* detection: the envelope's file type comes from the content, not the name alone.
* per-job parameters: AUTHENTICODE_REV / AUTHENTICODE_SCRIPTS are taken per job (HostRunner
  params), validated, forwarded to the agent, recorded in the Record, and refused when bad.
* the door summaries (pool_manager / orchestrator) carry the revocation-aware status and the
  full warnings next to myatg's raw verdict.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import io
import json
import threading
from pathlib import Path

import pytest
from blastbox.limits import Limits

from winval_blastbox import engine as eng
from winval_blastbox.host_runner import HostRunner

FIX = Path(__file__).parent / "fixtures" / "myatg"


def _load(name: str) -> dict:
    return json.loads((FIX / name).read_text())


class _Pool:
    def __init__(self, verdict: dict) -> None:
        self.verdict, self.calls = verdict, []

    def validate(self, path: str, params=None) -> dict:
        self.calls.append(params)
        return copy.deepcopy(self.verdict)


@pytest.fixture
def pool(monkeypatch):
    def use(verdict: dict) -> _Pool:
        p = _Pool(verdict)
        monkeypatch.setattr(eng, "get_pool", lambda stop_event=None: p)
        return p
    return use


def _sample(tmp_path: Path, name: str = "sample.exe", data: bytes = b"MZ" + b"\0" * 62) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _detonate(tmp_path, name="sample.exe", data=b"MZ" + b"\0" * 62):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return eng.AuthenticodeEngine().detonate(_sample(tmp_path, name, data), out, Limits())


# --- schema version ------------------------------------------------------------------------
def test_record_names_its_schema_version(tmp_path, pool):
    pool(_load("valid_script_graveyard_hit.json"))
    assert _detonate(tmp_path).payload.fields["schema_version"] == eng.SCHEMA_VERSION == "authenticode-record/2"


# --- status vocabulary ---------------------------------------------------------------------
def test_known_status_carries_no_unrecognised_warning(tmp_path, pool):
    pool(_load("untrusted_root.json"))
    assert "status_unrecognized" not in {w.code for w in _detonate(tmp_path).warnings}


def test_unknown_status_is_said(tmp_path, pool):
    v = _load("untrusted_root.json")
    v["status"] = "Incompatible"   # MapPs passes an unmapped PowerShell status through verbatim
    pool(v)
    r = _detonate(tmp_path)
    assert r.payload.fields["status"] == "Incompatible"
    w = [w for w in r.warnings if w.code == "status_unrecognized"]
    assert len(w) == 1 and "Incompatible" in w[0].message


@pytest.mark.parametrize("status", sorted(eng.MYATG_STATUSES))
def test_every_known_status_is_a_contract_detection(status):
    toml = (Path(__file__).parent.parent / "blastbox-engine.toml").read_text()
    assert f'code = "authenticode.status.{status}"' in toml


# --- RDP shape -----------------------------------------------------------------------------
def test_rdp_findings_are_indexed_and_the_file_is_hashed(tmp_path, pool):
    v = _load("rdp_expired.json")
    v["unsigned_dangerous"] = ["full address", "alternate shell"]
    pool(v)
    data = b"full address:s:10.0.0.1\r\nsignscope:s:Full Address\r\n"
    f = _detonate(tmp_path, "f01392.rdp", data).payload.fields
    assert f["file_sha256"] == hashlib.sha256(data).hexdigest()
    assert f["rdp_file_name"] == "f01392.rdp"
    assert (f["rdp_signscope_count"], f["rdp_total_settings"], f["rdp_unsigned_settings"]) == (26, 51, 25)
    assert json.loads(f["rdp_unsigned_dangerous"]) == ["full address", "alternate shell"]


def test_myatg_hash_is_kept_when_present(tmp_path, pool):
    v = _load("untrusted_root.json")
    pool(v)
    f = _detonate(tmp_path).payload.fields
    assert f["file_sha256"] == v["file_sha256"]
    assert f["rdp_unsigned_dangerous"] is None and f["rdp_file_name"] is None


# --- detection by content ------------------------------------------------------------------
def _ole(root_clsid: bytes, dir_sect: int = 0) -> bytes:
    """A minimal OLE compound file (512-byte sectors, first directory sector 0) whose root entry carries `root_clsid`.
    An MSI's root CLSID is {000C1084-...}; a Word .doc's is {00020906-...}: the OLE magic alone cannot tell them apart."""
    hdr = bytearray(512)
    hdr[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    hdr[0x1E:0x20] = (9).to_bytes(2, "little")     # sector shift: 512
    hdr[0x30:0x34] = dir_sect.to_bytes(4, "little")   # first directory sector
    root = bytearray(128)
    root[0x50:0x60] = root_clsid
    return bytes(hdr) + b"\0" * (512 * dir_sect) + bytes(root) + b"\0" * 384


@pytest.mark.parametrize("name,data,label", [
    ("innocent.txt", b"MZ\x90\x00" + b"\0" * 60, "pe"),
    ("x.exe", _ole(b"\x84\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"), "msi"),
    ("x.doc", _ole(b"\x06\x09\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"), "ole"),
    ("x.bin", _ole(b"\x84\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46", dir_sect=20), "msi"),
    ("x.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 56, "msi"),
    ("a.ps1", b"Set-Content x.rdp -Value 'full address:s:evil'\r\n", "script"),
    ("b.rdp", b"\xff\xfe" + "screen mode id:i:2\r\nfull address:s:host\r\n".encode("utf-16-le"), "rdp"),
    ("x.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 56, "ole"),
    ("x.cab", b"MSCF\0\0\0\0" + b"\0" * 56, "cab"),
    ("x.bin", b"\x30\x82\x01\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02", "catalog"),
    ("a.rdp", b"screen mode id:i:2\r\nfull address:s:host\r\n", "rdp"),
    ("a.ps1", b"Write-Host hi\r\n", "script"),
    ("noext", b"\x01\x02\x03\x04", "binary"),
])
def test_detected_from_content(tmp_path, name, data, label):
    d = eng.AuthenticodeEngine().detect(_sample(tmp_path, name, data))
    assert d.label == label


def test_a_pe_named_rdp_is_a_pe(tmp_path):
    d = eng.AuthenticodeEngine().detect(_sample(tmp_path, "evil.rdp", b"MZ" + b"\0" * 62))
    assert d.label == "pe" and d.source == "authenticode:magic"


def test_extension_only_guess_is_low_confidence(tmp_path):
    d = eng.AuthenticodeEngine().detect(_sample(tmp_path, "a.vbs", b"MsgBox 1\r\n"))
    assert d.source == "authenticode:extension" and d.confidence < 1.0


# --- per-job parameters --------------------------------------------------------------------
def test_job_params_are_forwarded_and_recorded(tmp_path, pool):
    p = pool(_load("valid_script_graveyard_hit.json"))
    env = HostRunner(limits=Limits()).validate_to_dir(
        _sample(tmp_path), tmp_path / "out", params={"AUTHENTICODE_REV": "offline", "AUTHENTICODE_SCRIPTS": "ps"})
    assert env["status"] == "ok"
    assert p.calls == [{"rev": "offline", "scripts": "ps"}]
    f = env["payload"]["fields"]
    assert (f["param_rev"], f["param_scripts"]) == ("offline", "ps")


def test_job_params_override_the_environment(tmp_path, pool, monkeypatch):
    monkeypatch.setenv("AUTHENTICODE_REV", "online")
    p = pool(_load("valid_script_graveyard_hit.json"))
    HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out", params={"AUTHENTICODE_REV": "none"})
    assert p.calls == [{"rev": "none"}]


def test_environment_still_applies_without_job_params(tmp_path, pool, monkeypatch):
    monkeypatch.setenv("AUTHENTICODE_SCRIPTS", "native")
    p = pool(_load("valid_script_graveyard_hit.json"))
    env = HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out")
    assert p.calls == [{"scripts": "native"}]
    assert (env["payload"]["fields"]["param_rev"], env["payload"]["fields"]["param_scripts"]) == (None, "native")


@pytest.mark.parametrize("params", [
    {"AUTHENTICODE_REV": "cached"},
    {"AUTHENTICODE_SCRIPTS": "true"},
    {"AUTHENTICODE_GV": "x"},
    {"AUTHENTICODE_REV": 1},
])
def test_bad_job_params_are_refused_before_the_vm(tmp_path, pool, params):
    p = pool(_load("valid_script_graveyard_hit.json"))
    env = HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out", params=params)
    assert env["status"] == "rejected"
    assert p.calls == []


def test_validate_job_params_normalises():
    assert eng.validate_job_params({"AUTHENTICODE_REV": " offline ", "AUTHENTICODE_SCRIPTS": ""}) == {"AUTHENTICODE_REV": "offline"}
    assert eng.validate_job_params(None) == {}
    with pytest.raises(ValueError):
        eng.validate_job_params({"AUTHENTICODE_REV": "cached"})


def test_job_params_do_not_leak_between_threads(tmp_path, pool):
    pool(_load("valid_script_graveyard_hit.json"))
    seen = {}
    barrier = threading.Barrier(2)

    def run(tag, rev):
        with eng.job_params({"AUTHENTICODE_REV": rev}):
            barrier.wait()
            seen[tag] = eng.effective_knobs()["AUTHENTICODE_REV"]

    ts = [threading.Thread(target=run, args=("a", "online")), threading.Thread(target=run, args=("b", "none"))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert seen == {"a": "online", "b": "none"}
    assert eng.effective_knobs()["AUTHENTICODE_REV"] == ""


# --- door summaries ------------------------------------------------------------------------
def _envelope(tmp_path, pool, verdict, monkeypatch=None):
    pool(verdict)
    return HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out")


def _unchecked_valid():
    v = _load("valid_script_graveyard_hit.json")
    v["chain"]["revocation_checked"] = "unknown"
    return v


@pytest.mark.parametrize("door", ["pool_manager", "orchestrator"])
def test_door_summary_is_revocation_aware(tmp_path, pool, door):
    env = _envelope(tmp_path, pool, _unchecked_valid())
    if door == "pool_manager":
        from winval_blastbox.pool_manager import _extract_verdict as summarize
    else:
        from winval_blastbox.orchestrator import _authenticode_verdict as summarize
    s = summarize(env)
    assert s["status" if door == "pool_manager" else "verdict_status"] == "ValidRevocationUnchecked"
    assert s["myatg_status"] == "Valid" and s["verdict"]["status"] == "Valid"   # myatg's raw verdict alongside
    assert s["revocation"] == "unchecked"
    assert "graveyard_hit" in s["warnings"]   # codes, as before
    gv = [w for w in s["warning_details"] if w["code"] == "graveyard_hit"]
    assert gv and "matched_on=" in gv[0]["message"]


@pytest.mark.parametrize("envelope_status,pane_status", [("ok", "done"), ("engine_error", "error"), ("rejected", "error")])
def test_orchestrator_pane_keeps_its_lifecycle_status(tmp_path, pool, monkeypatch, envelope_status, pane_status):
    # the pane's `status` is its lifecycle (queued/running/done/error); the engine's revocation-aware status rides beside it
    # and must not overwrite it (an engine_error pane read status=None, a Valid one read 'Valid' instead of 'done')
    import winval_blastbox.orchestrator as orch
    env = _envelope(tmp_path, pool, _unchecked_valid())
    if envelope_status != "ok":
        env = {"status": envelope_status, "payload": {"fields": {}}, "warnings": [], "artifacts": []}
    monkeypatch.setitem(orch.ENGINES, "authenticode", lambda p, params=None: orch._authenticode_verdict(env))
    store = orch.JobStore(max_workers=1)
    jid = store.create("a.exe", ["authenticode"])
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ")
    store._run_inner(jid, str(f), ["authenticode"])
    pane = store.get(jid)["engines"]["authenticode"]
    assert pane["status"] == pane_status
    row = store.list_jobs()[0]
    if envelope_status == "ok":
        assert pane["verdict_status"] == "ValidRevocationUnchecked"
        assert row["verdict"] == "ValidRevocationUnchecked" and row["myatg_status"] == "Valid"
    else:
        assert row["verdict"] is None


def _ingress(monkeypatch, tmp_path):
    from blastbox.host.jobs.memory import InMemoryJobStore
    import winval_blastbox.ingress as ingress
    monkeypatch.setattr(ingress, "_store", InMemoryJobStore())
    monkeypatch.setattr(ingress, "JOB_ROOT", tmp_path / "jobs")
    return ingress


def _done_job(ingress, env):
    from blastbox.host.jobs.base import Job, JobStatus
    from winval_blastbox.pool_manager import _extract_verdict
    j = Job.new(engine="authenticode", filename="s.exe")
    ingress._store.create(j)
    ingress._store.update(j.job_id, status=JobStatus.DONE, result_summary=_extract_verdict(env))
    return j


def test_ingress_lists_the_revocation_aware_status(tmp_path, pool, monkeypatch):
    ingress = _ingress(monkeypatch, tmp_path)
    env = _envelope(tmp_path, pool, _unchecked_valid())
    j = _done_job(ingress, env)
    row = ingress.jobs()["jobs"][0]
    assert row["verdict"] == "ValidRevocationUnchecked" and row["myatg_status"] == "Valid"
    assert row["revocation"] == "unchecked" and row["graveyard_hit"] is True
    rs = ingress.scan_status(j.job_id)["result_summary"]
    assert rs["status"] == "ValidRevocationUnchecked" and rs["verdict"]["status"] == "Valid"
    tbs = env["payload"]["fields"]["signer_tbs_sha256"]
    assert ingress.cert(tbs)["seen_in"][0]["status"] == "ValidRevocationUnchecked"


class _Upload:
    def __init__(self, name, data):
        self.filename, self._f = name, io.BytesIO(data)

    async def read(self, n=-1):
        return self._f.read(n)


def test_ingress_takes_per_job_params(tmp_path, monkeypatch):
    ingress = _ingress(monkeypatch, tmp_path)
    r = asyncio.run(ingress.scan(file=_Upload("a.exe", b"MZ"), rev="offline", scripts="ps"))
    assert ingress._store.get(r["job_id"]).params == {"AUTHENTICODE_REV": "offline", "AUTHENTICODE_SCRIPTS": "ps"}
    r = asyncio.run(ingress.scan(file=_Upload("a.exe", b"MZ"), rev="", scripts=""))
    assert ingress._store.get(r["job_id"]).params == {}


@pytest.mark.parametrize("rev,scripts", [("cached", ""), ("", "true")])
def test_ingress_refuses_bad_params_before_spooling(tmp_path, monkeypatch, rev, scripts):
    from fastapi import HTTPException
    ingress = _ingress(monkeypatch, tmp_path)
    with pytest.raises(HTTPException) as e:
        asyncio.run(ingress.scan(file=_Upload("a.exe", b"MZ"), rev=rev, scripts=scripts))
    assert e.value.status_code == 400
    assert not (tmp_path / "jobs").exists() or not any((tmp_path / "jobs").iterdir())


def test_pool_manager_forwards_job_params(tmp_path, monkeypatch):
    import winval_blastbox.pool_manager as pm
    seen = {}

    class _Runner:
        def validate_to_dir(self, inp, out, params=None):
            seen["params"] = params
            raise RuntimeError("stop here")

    from blastbox.host.jobs.base import Job, JobStatus
    from blastbox.host.jobs.memory import InMemoryJobStore
    root, work = tmp_path / "jobs", tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(pm, "JOB_ROOT", root)
    monkeypatch.setattr(pm, "WORK_ROOT", work)
    monkeypatch.setattr(pm._rel_parts, "__defaults__", (root,))
    mgr = pm.PoolManager.__new__(pm.PoolManager)
    mgr._store, mgr._runner = InMemoryJobStore(), _Runner()
    j = Job.new(engine="authenticode", filename="a.exe")
    j.params = {"AUTHENTICODE_REV": "none"}
    j.result_dir = str(root / j.job_id)
    (root / j.job_id / "input").mkdir(parents=True)
    (root / j.job_id / "input" / "a.exe").write_bytes(b"MZ")
    mgr._store.create(j)
    mgr._store.update(j.job_id, status=JobStatus.RUNNING)
    mgr._process(mgr._store.get(j.job_id))
    assert seen["params"] == {"AUTHENTICODE_REV": "none"}


def test_orchestrator_forwards_job_params(tmp_path, monkeypatch):
    import winval_blastbox.orchestrator as orch
    seen = {}
    monkeypatch.setitem(orch.ENGINES, "authenticode", lambda p, params=None: seen.setdefault("params", params) and {} or {})
    store = orch.JobStore(max_workers=1)
    jid = store.create("a.exe", ["authenticode"])
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ")
    store._run_inner(jid, str(f), ["authenticode"], {"AUTHENTICODE_SCRIPTS": "ps"})
    assert seen["params"] == {"AUTHENTICODE_SCRIPTS": "ps"}


def _manager_job(tmp_path, monkeypatch, runner, params):
    import winval_blastbox.pool_manager as pm
    from blastbox.host.jobs.base import Job, JobStatus
    from blastbox.host.jobs.memory import InMemoryJobStore
    root, work = tmp_path / "jobs", tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(pm, "JOB_ROOT", root)
    monkeypatch.setattr(pm, "WORK_ROOT", work)
    monkeypatch.setattr(pm._rel_parts, "__defaults__", (root,))
    mgr = pm.PoolManager.__new__(pm.PoolManager)
    mgr._store, mgr._runner = InMemoryJobStore(), runner
    j = Job.new(engine="authenticode", filename="a.exe")
    j.params = params
    j.result_dir = str(root / j.job_id)
    (root / j.job_id / "input").mkdir(parents=True)
    (root / j.job_id / "input" / "a.exe").write_bytes(b"MZ" + b"\0" * 62)
    mgr._store.create(j)
    mgr._store.update(j.job_id, status=JobStatus.RUNNING)
    mgr._process(mgr._store.get(j.job_id))
    return mgr._store.get(j.job_id)


def test_pool_manager_records_a_rejected_param_as_failed(tmp_path, monkeypatch, pool):
    p = pool(_load("valid_script_graveyard_hit.json"))
    j = _manager_job(tmp_path, monkeypatch, HostRunner(limits=Limits()), {"AUTHENTICODE_REV": "cached"})
    assert j.status.value == "failed" and "AUTHENTICODE_REV" in (j.error or "")
    assert j.result_summary["envelope_status"] == "rejected" and p.calls == []


def test_pool_manager_records_the_revocation_aware_status(tmp_path, monkeypatch, pool):
    pool(_unchecked_valid())
    j = _manager_job(tmp_path, monkeypatch, HostRunner(limits=Limits()), {"AUTHENTICODE_REV": "online"})
    assert j.status.value == "done"
    assert j.result_summary["status"] == "ValidRevocationUnchecked" and j.result_summary["verdict"]["status"] == "Valid"


@pytest.mark.parametrize("rev,scripts", [("cached", ""), ("", "1")])
def test_orchestrator_refuses_bad_params(monkeypatch, rev, scripts):
    from fastapi import HTTPException
    import winval_blastbox.orchestrator as orch
    monkeypatch.setattr(orch, "_store", object())
    with pytest.raises(HTTPException) as e:
        asyncio.run(orch.scan(file=_Upload("a.exe", b"MZ"), engines="", rev=rev, scripts=scripts))
    assert e.value.status_code == 400


def test_ingress_param_vocabulary_is_the_engines():
    import winval_blastbox.ingress as ingress
    assert {k: "|".join(v) for k, v in ingress._PARAM_FIELDS.values()} == eng.KNOB_VALUES


def test_valid_without_a_chain_reports_revocation_unchecked():
    # myatg's scripts=ps branch can answer Valid with chain:null (PowerShell's verdict, no embedded PKCS#7 parsed): no
    # revocation was evaluated, so the Record says `unchecked` (the contract's source for ValidRevocationUnchecked), not
    # null (which means "no chain evaluated: NotSigned / error skeleton")
    v = _load("valid_script_graveyard_hit.json")
    v["chain"] = None
    f = eng._summary(v).fields
    assert f["status"] == "ValidRevocationUnchecked"
    assert f["revocation"] == "unchecked"
    n = _load("valid_script_graveyard_hit.json")
    n["status"], n["chain"] = "NotSigned", None
    assert eng._summary(n).fields["revocation"] is None


def test_ingress_derives_the_revocation_aware_status_for_pre_upgrade_rows(monkeypatch, tmp_path):
    # a row the previous pool-manager wrote has myatg's raw verdict but no engine `status`: the door applies the engine's
    # rule to that verdict rather than showing myatg's bare Valid
    from blastbox.host.jobs.base import Job, JobStatus
    ingress = _ingress(monkeypatch, tmp_path)
    v = _unchecked_valid()
    j = Job.new(engine="authenticode", filename="old.exe")
    ingress._store.create(j)
    ingress._store.update(j.job_id, status=JobStatus.DONE, result_summary={"verdict": v, "warnings": [], "envelope_status": "ok"})
    assert ingress.jobs()["jobs"][0]["verdict"] == "ValidRevocationUnchecked"
    assert ingress.cert(v["signer"]["tbs_sha256"])["seen_in"][0]["status"] == "ValidRevocationUnchecked"


def test_door_summary_records_the_knobs_the_verdict_was_computed_under(tmp_path, pool):
    # the door shows which rev/scripts applied (Job.params is stripped from the public job), so a client that misnamed a
    # form field can see its value did not apply
    pool(_unchecked_valid())
    env = HostRunner(limits=Limits()).validate_to_dir(_sample(tmp_path), tmp_path / "out", params={"AUTHENTICODE_REV": "none"})
    s = eng.summarize_envelope(env)
    assert s["param_rev"] == "none"
    assert "param_scripts" in s

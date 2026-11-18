"""A Valid verdict whose revocation half was never checked is not reported as plain Valid.

myatg answers status=Valid when the CRL/OCSP responders were unreachable (chain.revocation_checked
"unknown") or when revocation checking was switched off (AUTHENTICODE_REV=none -> "none"). The
engine's Record therefore carries ``revocation`` (checked_good | revoked | unchecked | error | null)
and rewrites such a Valid to ``ValidRevocationUnchecked``; myatg's own string stays in
``myatg_status`` (and verbatim in authenticode_json).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from winval_blastbox.engine import _summary

FIX = Path(__file__).parent / "fixtures" / "myatg"


def _load(name: str) -> dict:
    return json.loads((FIX / name).read_text())


def _valid(revocation_checked):
    v = copy.deepcopy(_load("valid_script_graveyard_hit.json"))
    if revocation_checked is _MISSING:
        v["chain"].pop("revocation_checked", None)
    else:
        v["chain"]["revocation_checked"] = revocation_checked
    return v


_MISSING = object()


@pytest.mark.parametrize("rc", ["online", "offline"])
def test_checked_valid_stays_valid(rc):
    f = _summary(_valid(rc)).fields
    assert (f["status"], f["myatg_status"], f["revocation"]) == ("Valid", "Valid", "checked_good")


@pytest.mark.parametrize("rc", ["unknown", "none"])
def test_unchecked_valid_is_not_plain_valid(rc):
    f = _summary(_valid(rc)).fields
    assert f["status"] == "ValidRevocationUnchecked"
    assert f["myatg_status"] == "Valid"
    assert f["revocation"] == "unchecked"
    assert f["chain_revocation_checked"] == rc   # the why (unreachable vs switched off) stays indexed


@pytest.mark.parametrize("rc", ["sometime-later", 7, _MISSING, None])
def test_unrecognised_revocation_answer_is_error_not_good(rc):
    f = _summary(_valid(rc)).fields
    assert f["revocation"] == "error"
    assert f["status"] == "ValidRevocationUnchecked"


def test_unchecked_and_fully_checked_records_differ():
    good = _summary(_valid("online")).fields
    bad = _summary(_valid("unknown")).fields
    assert good["status"] != bad["status"] and good["revocation"] != bad["revocation"]


@pytest.mark.parametrize("name", ["revoked_1.json", "revoked_2.json", "revoked_graveyard_hit.json"])
def test_revoked(name):
    f = _summary(_load(name)).fields
    assert (f["status"], f["myatg_status"], f["revocation"]) == ("Revoked", "Revoked", "revoked")


def test_revoked_chain_under_a_valid_status_is_reported_revoked():
    v = _valid("online")
    v["chain"]["revoked"] = True
    f = _summary(v).fields
    assert (f["status"], f["revocation"]) == ("Revoked", "revoked")


def test_non_valid_status_is_passed_through_with_revocation_state():
    f = _summary(_load("rdp_expired.json")).fields   # RDP verdict, responders unreachable
    assert (f["status"], f["myatg_status"], f["revocation"]) == ("Expired", "Expired", "unchecked")
    f = _summary(_load("untrusted_root.json")).fields
    assert (f["status"], f["revocation"]) == ("UntrustedRoot", "checked_good")


def test_no_chain_means_no_revocation_answer():
    f = _summary(_load("error_skeleton.json")).fields
    assert (f["status"], f["myatg_status"], f["revocation"]) == ("UnknownError", "UnknownError", None)

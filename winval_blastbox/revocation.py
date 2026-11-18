"""The revocation-aware verdict status, shared by the engine (Record fields) and the ingress door (rows written before
the pool-manager recorded the engine's status). Pure: no VM pool, no blastbox imports."""
from __future__ import annotations

# myatg's chain.revocation_checked vocabulary (myatg.cs / rdp_validate.cs): "online" / "offline" = the responders (or the
# CRL cache) answered; "unknown" = they were unreachable; "none" = checking switched off (AUTHENTICODE_REV=none).
_REV_CHECKED = frozenset({"online", "offline"})
_REV_UNCHECKED = frozenset({"unknown", "none"})

# The status the engine reports for myatg's Valid when revocation was not checked good.
VALID_REVOCATION_UNCHECKED = "ValidRevocationUnchecked"


def _revocation(chain: dict | None) -> str | None:
    """The revocation half of the verdict, explicit: checked_good | revoked | unchecked | error, or None (no chain evaluated).

    Fail-closed: a revocation_checked value outside myatg's known vocabulary (or a chain without one) is "error", never good."""
    if not chain:
        return None
    if chain.get("revoked") is True:
        return "revoked"
    rc = chain.get("revocation_checked")
    if isinstance(rc, str) and rc in _REV_CHECKED:
        return "checked_good"
    if isinstance(rc, str) and rc in _REV_UNCHECKED:
        return "unchecked"
    return "error"


def _status(myatg_status: object, revocation: str | None) -> object:
    """myatg's status, except that Valid is never claimed unless revocation was checked good.

    myatg answers Valid when the responders were unreachable or checking was off; reported verbatim that made such a Record
    indistinguishable from a fully checked one. A revoked chain under Valid is reported Revoked."""
    if myatg_status != "Valid" or revocation == "checked_good":
        return myatg_status
    return "Revoked" if revocation == "revoked" else VALID_REVOCATION_UNCHECKED


def verdict_revocation(verdict: dict) -> str | None:
    """_revocation of the verdict's chain; a Valid verdict with no chain (myatg's scripts=ps branch) checked nothing."""
    chain = verdict.get("chain")
    revocation = _revocation(chain if isinstance(chain, dict) else None)
    if revocation is None and verdict.get("status") == "Valid":
        return "unchecked"
    return revocation


def verdict_status(verdict: dict) -> object:
    """The engine's status for a raw myatg verdict: Valid only when revocation was checked good."""
    return _status(verdict.get("status"), verdict_revocation(verdict))


def verdict_cert_tbs(verdict: object) -> list[str]:
    """The lower-cased tbs_sha256 of the signer and every chain element, skipping anything that is not a string: the verdict
    is the guest's answer, and one stored row with a non-string value made every /cert lookup on a door a 500."""
    if not isinstance(verdict, dict):
        return []
    out = []
    signer = verdict.get("signer")
    chain = verdict.get("chain")
    elems = chain.get("chain") if isinstance(chain, dict) else None
    for c in [signer, *(elems if isinstance(elems, list) else [])]:
        t = c.get("tbs_sha256") if isinstance(c, dict) else None
        if isinstance(t, str) and t:
            out.append(t.lower())
    return out

"""The blastbox ``authenticode`` engine — wraps the myatg Windows validator.

Unlike ClippyShot/RedTusk, whose ``detonate()`` runs *inside* a disposable Linux
container that the blastbox dispatcher ``docker run``s, this engine's disposable
worker is a **Windows VM** (libvirt overlay clone off the golden, driven over TCP
by :mod:`winval_blastbox.pool`). The VM *is* the sandbox, so the engine runs
host-side and delegates isolation to the VM pool. It is therefore driven by the
in-process host runner (:mod:`winval_blastbox.host_runner`) via
``blastbox.worker.harness.run_detonation`` rather than by the container dispatcher.

Per file the engine returns the full myatg verdict three ways, belt-and-suspenders:
  * a structured :class:`Record` summary (the indexed/searchable fields),
  * the verbatim verdict JSON embedded as the ``authenticode_json`` string field
    (the ClippyShot ``clippyshot_metadata`` pattern — nothing is lost), and
  * the same JSON written to the ``authenticode.json`` artifact on disk.

The myatg tool itself never raises on a bad/unsigned/corrupt file — it emits a
full JSON skeleton with ``status`` set accordingly — so a returned verdict is
always "ok". Only a transport/VM failure (pool unreachable, agent dead) raises,
which the harness turns into a clean ``engine_error`` envelope.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from blastbox.contract import DeclaredArtifact, Detection, Record
from blastbox.contract import Warning as BbWarning
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

from .vm_pool import WarmVmPool

# ---------------------------------------------------------------------------
# Module-level VM pool singleton (blastbox WarmPool over LibvirtVmRuntime, Phase 3).
#
# Booting the Windows workers is expensive (~70-84s/VM), so the pool is created once per process
# and reused. warmup() pays for it up front; detonate() lazily starts it if warmup() wasn't called.
# Reuse cadence (jobs_per_recycle) is read from the engine's risk×cost declaration.
# ---------------------------------------------------------------------------
_POOL: WarmVmPool | None = None
_POOL_LOCK = threading.Lock()


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def get_pool() -> WarmVmPool:
    """Return the started WarmPool-backed VM pool, booting it on first use (thread-safe)."""
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:  # double-checked: concurrent first-detonate must not boot two pools
                # reuse cadence: the engine's own risk×cost call (parse-only myatg → 25), but an
                # operator can override at RUNTIME via AUTHENTICODE_JOBS_PER_RECYCLE — set 1 to
                # snapshot-revert ("clear the job") after EVERY validation (max isolation, ~6-8s/job)
                # vs reuse-then-recycle for throughput. Smoke gating is independent (AUTHENTICODE_
                # SMOKE_SAMPLE → health_check runs before the snapshot + after every recycle).
                jpr = int(os.environ.get("AUTHENTICODE_JOBS_PER_RECYCLE",
                                         getattr(AuthenticodeEngine, "jobs_per_recycle", 1)))
                pool = WarmVmPool(jobs_per_recycle=jpr)
                pool.start()
                _POOL = pool
    return _POOL


def shutdown_pool() -> None:
    """Destroy every VM worker (host-runner shutdown / SIGTERM)."""
    global _POOL
    if _POOL is not None:
        try:
            _POOL.shutdown()
        finally:
            _POOL = None


# Per-job param keys a client may set (forwarded by the orchestrator through the
# blastbox allowlist as BLASTBOX_ENGINE_AUTHENTICODE_PARAM_KEYS). These tune the
# in-guest myatg invocation; see host_runner / the design doc §3a.
PARAM_KEYS = frozenset(
    {"AUTHENTICODE_REV", "AUTHENTICODE_SCRIPTS", "AUTHENTICODE_GV", "AUTHENTICODE_TIER"}
)

# Extension → (detection label, mime) for the file-type tag on the envelope.
_EXT_TYPE = {
    ".exe": ("pe", "application/vnd.microsoft.portable-executable"),
    ".dll": ("pe", "application/vnd.microsoft.portable-executable"),
    ".sys": ("pe", "application/vnd.microsoft.portable-executable"),
    ".msi": ("msi", "application/x-msi"),
    ".cab": ("cab", "application/vnd.ms-cab-compressed"),
    ".cat": ("catalog", "application/octet-stream"),
    ".ps1": ("script", "text/plain"),
    ".vbs": ("script", "text/plain"),
    ".js": ("script", "text/plain"),
    ".rdp": ("rdp", "text/plain"),
}

_SCALAR = (str, int, float, bool)


def _scalar(v: object) -> str | int | float | bool | None:
    """Coerce an arbitrary JSON value to a Record scalar."""
    if v is None or isinstance(v, _SCALAR):
        return v
    return json.dumps(v, separators=(",", ":"), default=str)


def _summary(verdict: dict) -> Record:
    """Flatten the myatg verdict into the indexed Record summary fields.

    Every lookup is defensive ``.get()`` — myatg's error/oversize skeletons carry
    null/empty values, and the schema may grow.
    """
    signer = verdict.get("signer") or {}
    chain = verdict.get("chain") or {}
    grave = verdict.get("graveyard") or {}
    tsa = verdict.get("timestamper") or {}

    fields: dict[str, object] = {
        "file_sha256": verdict.get("file_sha256"),
        "status": verdict.get("status"),
        "signature_type": verdict.get("signature_type"),
        "content_verified": verdict.get("content_verified"),
        "is_os_binary": verdict.get("is_os_binary"),
        "timestamped": verdict.get("timestamped"),
        "sign_time": verdict.get("sign_time"),
        "sign_time_verified": verdict.get("sign_time_verified"),
        # signer (the leaf code-signing cert)
        "signer_subject_cn": signer.get("subject_cn"),
        "signer_issuer_cn": signer.get("issuer_cn"),
        "signer_serial_number": signer.get("serial_number"),
        "signer_thumbprint": signer.get("thumbprint"),
        "signer_sha1_fingerprint": signer.get("sha1_fingerprint"),
        "signer_sha256_fingerprint": signer.get("sha256_fingerprint"),
        "signer_tbs_sha256": signer.get("tbs_sha256"),
        "signer_eku_codesigning": signer.get("eku_codesigning"),
        "signer_self_signed": signer.get("self_signed"),
        "signer_not_before": signer.get("not_before"),
        "signer_not_after": signer.get("not_after"),
        # chain
        "chain_len": len(chain.get("chain") or []),
        "chain_explicit_distrust": chain.get("explicit_distrust"),
        "chain_valid_at_sign_time": chain.get("valid_at_sign_time"),
        # timestamper
        "timestamper_subject_cn": tsa.get("subject_cn"),
        "timestamper_tbs_sha256": tsa.get("tbs_sha256"),
        # graveyard
        "graveyard_hit": grave.get("hit"),
        "graveyard_matched_on": grave.get("matched_on"),
        "graveyard_malware": grave.get("malware"),
        "graveyard_malware_type": grave.get("malware_type"),
    }
    return Record(fields={k: _scalar(v) for k, v in fields.items()})


class AuthenticodeEngine:
    """blastbox engine: Windows Authenticode / cert-graveyard verdict via myatg."""

    name: str = "authenticode"
    formats: frozenset[str] = frozenset({"*"})

    # Reset policy (read by the warm pool; default for ANY engine is 1 = reset every job).
    # myatg only PARSES the sample's signature (WinVerifyTrust / ASN.1 / SignedCms) — it never
    # executes, renders, or opens a network connection *to the sample's content* — so the residual
    # risk is a signature-parser exploit, contained to the throwaway VM + the NETWORK SERVICE LIMITED
    # account. That low threat profile is what earns warm REUSE: serve N jobs, then snapshot-revert.
    # An engine that RENDERS or EXECUTES untrusted input (ClippyShot's LibreOffice, a headless
    # browser, any detonation engine) MUST leave this at 1 — it actually runs the malicious content,
    # so every job needs a pristine worker.
    jobs_per_recycle: int = 25

    def detect(self, input: Path) -> Detection:
        label, mime = _EXT_TYPE.get(input.suffix.lower(), ("binary", "application/octet-stream"))
        return Detection(label=label, mime=mime, confidence=1.0, source="authenticode")

    def warmup(self) -> None:
        """Pre-pay the VM-pool boot for the host runner (optional)."""
        get_pool()

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        # The VM pool provides isolation + recycle; a transport/VM failure raises
        # and the harness writes a clean engine_error envelope.
        verdict = get_pool().validate(str(input))

        warnings: list[BbWarning] = []
        # Per-job param forwarding to the in-guest agent is not wired yet: the
        # agent transport is [filename][bytes] only, so myatg runs with the
        # operator-baked guest defaults. Surface any client-requested override so
        # the result is honest about what was (not) applied.
        requested = {k: os.environ[k] for k in PARAM_KEYS if os.environ.get(k)}
        if requested:
            warnings.append(
                BbWarning(
                    code="param_not_forwarded",
                    message=(
                        "per-job myatg params not yet plumbed to the guest agent; "
                        "used guest defaults: " + ",".join(sorted(requested))
                    ),
                )
            )

        raw = json.dumps(verdict, separators=(",", ":"), default=str)
        (outdir / "authenticode.json").write_text(raw, encoding="utf-8")

        summary = _summary(verdict)
        # Embed the verbatim verdict so the full chain survives in the envelope,
        # not only in the artifact (the ClippyShot clippyshot_metadata pattern).
        summary.fields["authenticode_json"] = raw

        # A graveyard hit is a strong malicious signal — surface it as a warning.
        grave = verdict.get("graveyard") or {}
        if grave.get("hit"):
            warnings.append(
                BbWarning(
                    code="graveyard_hit",
                    message=(
                        f"signing cert in graveyard (matched_on={grave.get('matched_on')}, "
                        f"malware={grave.get('malware')})"
                    ),
                )
            )

        return DetonationResult(
            payload=summary,
            artifacts=[DeclaredArtifact(id="authenticode", path="authenticode.json", kind="json")],
            detected=self.detect(input),
            warnings=warnings,
            status="ok",
        )


if __name__ == "__main__":
    import sys

    from blastbox.worker.harness import main

    sys.exit(main(AuthenticodeEngine()))

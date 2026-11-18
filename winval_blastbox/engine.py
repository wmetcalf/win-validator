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

import contextlib
import contextvars
import hashlib
import json
import os
import re
import threading
from collections.abc import Iterator, Mapping
from pathlib import Path

from blastbox.contract import DeclaredArtifact, Detection, Record
from blastbox.contract import Warning as BbWarning
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

from .knobs import env_int
from .revocation import _status, verdict_revocation
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



KNOB_VALUES = {"AUTHENTICODE_REV": "online|offline|none", "AUTHENTICODE_SCRIPTS": "ps|native"}   # winval.env.example's vocabulary
KNOB_FALLBACK = {"AUTHENTICODE_REV": "the agent read it as online", "AUTHENTICODE_SCRIPTS": "the agent read it as native (only the exact word ps selects PowerShell)"}   # myatg's ternaries, unvalidated
_KNOB_PARAM = {"AUTHENTICODE_REV": "rev", "AUTHENTICODE_SCRIPTS": "scripts"}   # the agent's query parameter for each knob
# What the agent's ternaries read an unknown value as (KNOB_FALLBACK, in words): the engine sends THIS, never the raw value, so
# a malformed env value (an unclosed quote hands systemd the rest of the file) reaches neither the guest nor the Record.
_KNOB_FALLBACK_VALUE = {"AUTHENTICODE_REV": "online", "AUTHENTICODE_SCRIPTS": "native"}

# Per-job values for the knobs above (blastbox Job.params; set by HostRunner around one run_detonation). A ContextVar,
# not os.environ: the pool-manager and the orchestrator run several jobs at once in threads of ONE process.
_JOB_PARAMS: contextvars.ContextVar[Mapping[str, str] | None] = contextvars.ContextVar("authenticode_job_params", default=None)


def validate_job_params(params: Mapping[str, object] | None) -> dict[str, str]:
    """The per-job knobs, stripped, blanks dropped. Raises ValueError naming the first key or value the agent does not know:
    a per-job value comes from a client, so it is refused (the job is sealed ``rejected``, the door answers 400) rather than
    sent as what the agent reads it as (_KNOB_FALLBACK_VALUE), with a warning, as an operator's environment typo is."""
    out: dict[str, str] = {}
    for k, v in (params or {}).items():
        if k not in KNOB_VALUES:
            raise ValueError(f"{str(k)[:64]!r} is not a per-job parameter of this engine (known: {', '.join(KNOB_VALUES)})")
        if not isinstance(v, str):
            raise ValueError(f"{k} must be a string, not {type(v).__name__}")
        v = v.strip()
        if not v:
            continue
        if v not in KNOB_VALUES[k].split("|"):
            raise ValueError(f"{k}={v[:64]!r} is not a value the agent knows ({KNOB_VALUES[k]})")
        out[k] = v
    return out


@contextlib.contextmanager
def job_params(params: Mapping[str, object] | None) -> Iterator[None]:
    """Run the enclosed detonation under these per-job knobs (unvalidated here: precheck() refuses a bad one)."""
    token = _JOB_PARAMS.set(dict(params or {}))
    try:
        yield
    finally:
        _JOB_PARAMS.reset(token)


def effective_knobs() -> dict[str, str]:
    """Each knob's value for the current job: the per-job value when the job set one, else the process environment ('' = unset)."""
    per_job = _JOB_PARAMS.get() or {}
    out = {}
    for k in KNOB_VALUES:
        v = per_job.get(k)
        v = v.strip() if isinstance(v, str) else ""
        out[k] = v or (os.environ.get(k) or "").strip()   # stripped like every knob: whitespace-only is unset
    return out


# The only shape of unknown knob value echoed back: a short plain token (a typo like 'onlin' or 'PS'). Anything else may carry
# the rest of the env file (unclosed quote, backslash-newline continuation), secrets included.
_SHOWABLE_KNOB = re.compile(r"[A-Za-z0-9_-]{1,16}")


def _raw_knobs() -> dict[str, str]:
    """Each knob's UNSTRIPPED source value (per-job, else environment): strip() would hide that a value spans lines."""
    per_job = _JOB_PARAMS.get() or {}
    out = {}
    for k in KNOB_VALUES:
        v = per_job.get(k)
        out[k] = v if isinstance(v, str) and v.strip() else (os.environ.get(k) or "")
    return out


def unknown_knob_values() -> dict[str, str]:
    """The per-verdict knobs whose (stripped) value names nothing the agent knows: the agent reads such a value as its fallback
    (KNOB_FALLBACK: rev -> online, scripts -> native) and says nothing, so the verdict carries a warning naming the knob instead."""
    out = {}
    for k, v in effective_knobs().items():
        if v and v not in KNOB_VALUES[k].split("|"):
            out[k] = v
    return out


def knob_warnings() -> list[BbWarning]:
    """One warning per knob whose value the agent does not know (the engine sends the agent's fallback reading instead).
    An unclosed quote or a backslash-newline continuation hands systemd the next env-file lines as the value, secrets included:
    only a short plain token (_SHOWABLE_KNOB) is echoed, anything else by its length. The MESSAGE is capped at the contract's 2000."""
    out: list[BbWarning] = []
    raw = _raw_knobs()
    for k, bad in unknown_knob_values().items():
        if _SHOWABLE_KNOB.fullmatch(raw.get(k, "").strip()):
            shown = repr(bad)
        else:   # an unclosed quote or a backslash-newline continuation pulls the next env-file lines in: show only the size
            shown = f"<a {len(raw.get(k, ''))}-character value, not shown>"
        msg = f"{k}={shown} is not a value the agent knows ({KNOB_VALUES[k]}); {KNOB_FALLBACK[k]}"
        out.append(BbWarning(code="param_unknown_value", message=msg[:2000]))
    return out


def _no_lone_surrogates(v: object) -> object:
    """The verdict with every unpaired UTF-16 surrogate (myatg's J() writes \\uD800 for one; json.loads keeps it) escaped as
    text: a lone surrogate in any string made BbWarning raise or the envelope fail to serialise, dropping the verdict."""
    if isinstance(v, str):
        if v.isascii():
            return v
        try:
            v.encode("utf-8")   # C-speed probe: only a string holding a lone surrogate fails it
            return v
        except UnicodeEncodeError:
            return v.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(v, dict):
        return {_no_lone_surrogates(k): _no_lone_surrogates(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_no_lone_surrogates(x) for x in v]
    return v


def get_pool(stop_event=None) -> WarmVmPool:
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
                jpr = env_int("AUTHENTICODE_JOBS_PER_RECYCLE", int(getattr(AuthenticodeEngine, "jobs_per_recycle", 1)), floor=1)
                pool = WarmVmPool(jobs_per_recycle=jpr)
                pool.start(stop_event=stop_event)   # reaps its own workers on every failed exit; nothing else can
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


# Per-job parameters: both doors' /scan take optional `rev` / `scripts` form fields, stored as the Job's params
# {AUTHENTICODE_REV, AUTHENTICODE_SCRIPTS}; HostRunner runs the job under them (job_params) and they override the process
# environment for that job only. AUTHENTICODE_GV and AUTHENTICODE_TIER are read by nothing (the graveyard is GOLDEN_GRAVEYARD,
# baked into the golden's serve startup; TIER is not a myatg parameter): an operator who exports either into the ENGINE
# PROCESS gets a param_not_forwarded warning on every verdict (below), and a Job.params key naming either is refused (precheck).
# The doors take only the `rev` / `scripts` form fields: any other field (e.g. AUTHENTICODE_REV=) is ignored, and the job's
# summary records the knobs actually applied (param_rev / param_scripts).

SCHEMA_VERSION = "authenticode-record/2"   # the Record's field set; bump on any change to _summary()'s keys or meanings

# Every status myatg prints (myatg.cs, rdp_validate.cs). MapPs passes an unmapped PowerShell status through verbatim, so a
# status outside this set is possible; it is passed through too, with a status_unrecognized warning.
MYATG_STATUSES = frozenset({
    "Valid", "HashMismatch", "Revoked", "Distrusted", "UntrustedRoot", "Expired", "NotYetValid", "NotSigned", "UnknownError",
})

# Extension → (detection label, mime): the fallback when the content has no signature (text formats).
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

_MIME = {
    "pe": "application/vnd.microsoft.portable-executable",
    "msi": "application/x-msi",
    "ole": "application/x-ole-storage",
    "cab": "application/vnd.ms-cab-compressed",
    "catalog": "application/vnd.ms-pki.seccat",
    "rdp": "application/x-rdp",
    "script": "text/plain",
    "binary": "application/octet-stream",
}
_RDP_KEYS = (b"full address:s:", b"signscope:s:", b"screen mode id:i:", b"alternate shell:s:", b"remoteapplicationprogram:s:")
_SNIFF_BYTES = 4096
_RDP_LINE = re.compile(rb"^[a-z0-9 ]+:[sib]:")


_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# Root-entry CLSIDs (little-endian GUID bytes) of the Windows Installer family: MSI {000C1084-..}, MSP {000C1086-..},
# MST {000C1082-..}. Office documents (.doc/.xls/.ppt) are OLE compound files too, with other CLSIDs.
_MSI_CLSIDS = frozenset(bytes([b, 0x10, 0x0C, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46]) for b in (0x84, 0x86, 0x82))
_OLE_UNDETERMINED = "ole?"


def _ole_root_clsid_offset(head: bytes) -> int | None:
    """File offset of an OLE compound file's root-entry CLSID (the first directory entry), or None for a malformed header."""
    shift = int.from_bytes(head[0x1E:0x20], "little")
    if shift not in (9, 12) or len(head) < 0x34:
        return None
    sect = int.from_bytes(head[0x30:0x34], "little")
    if sect >= 0xFFFFFFFA:   # MAXREGSECT: ENDOFCHAIN/FREESECT etc. are not a directory sector
        return None
    return ((sect + 1) << shift) + 0x50


def _ole_kind(head: bytes) -> str:
    """msi / ole from an OLE compound file's root-entry CLSID, or _OLE_UNDETERMINED when the root entry is outside `head`."""
    off = _ole_root_clsid_offset(head)
    clsid = head[off:off + 16] if off is not None else b""
    if len(clsid) < 16:
        return _OLE_UNDETERMINED
    return "msi" if clsid in _MSI_CLSIDS else "ole"


def _sniff(head: bytes) -> str | None:
    """The file type from the first bytes, or None when nothing in them is decisive."""
    if head[:2] == b"MZ":
        return "pe"
    if head[:8] == _OLE_MAGIC:   # OLE compound file: an MSI, or an Office document, told apart by the root CLSID
        return _ole_kind(head)
    if head[:4] == b"MSCF":
        return "cab"
    # DER SEQUENCE carrying the PKCS#7 signedData OID (1.2.840.113549.1.7.2): a catalog / detached signature
    if head[:1] == b"\x30" and b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" in head[:64]:
        return "catalog"
    text = head.replace(b"\x00", b"").lower()   # .rdp files are often UTF-16LE
    for bom in (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff"):   # UTF-8 / UTF-16LE / UTF-16BE byte-order marks (NULs already gone)
        if text.startswith(bom):
            text = text[len(bom):]
    # an .rdp file is `name:type:value` lines: its FIRST line is one, and a known key starts a line (a script that merely
    # mentions 'full address:s:' mid-line is not an .rdp)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines and _RDP_LINE.match(lines[0]) and any(ln.startswith(k) for ln in lines for k in _RDP_KEYS):
        return "rdp"
    return None


# Every warning code detonate()/knob_warnings() write (the doors publish only these messages).
ENGINE_WARNING_CODES = frozenset({"graveyard_hit", "status_unrecognized", "param_unknown_value", "param_not_forwarded",
                                  "precheck_rejected", "file_sha256_mismatch"})

_SCALAR = (str, int, float, bool)


def _scalar(v: object) -> str | int | float | bool | None:
    """Coerce an arbitrary JSON value to a Record scalar."""
    if v is None or isinstance(v, _SCALAR):
        return v
    return json.dumps(v, separators=(",", ":"), default=str)


def _obj(v: object) -> dict:
    """A sub-object of the guest's verdict, or {} when it is missing or not an object."""
    return v if isinstance(v, dict) else {}


def _summary(verdict: dict, params: Mapping[str, str] | None = None) -> Record:
    """Flatten the myatg verdict into the indexed Record summary fields.

    ``params`` are the agent query parameters this verdict was computed under ({rev, scripts}; absent = agent default).

    Every lookup is defensive ``.get()`` — myatg's error/oversize skeletons carry
    null/empty values, and the schema may grow.
    """
    signer = _obj(verdict.get("signer"))   # the guest's answer: a truthy non-dict here must not raise (engine_error)
    chain = _obj(verdict.get("chain"))
    grave = _obj(verdict.get("graveyard"))
    tsa = _obj(verdict.get("timestamper"))

    revocation = verdict_revocation(verdict)
    params = params or {}
    # rdp_validate.cs's shape: only it names the file (its unsigned / oversize early returns carry no signscope_count)
    rdp = "file" in verdict or verdict.get("signature_type") == "RDP"
    fields: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "file_sha256": verdict.get("file_sha256"),
        # the engine's status: myatg's, with an unchecked-revocation Valid rewritten (see _status); myatg's own string is
        # myatg_status (and verbatim in authenticode_json)
        "status": _status(verdict.get("status"), revocation),
        "myatg_status": verdict.get("status"),
        "revocation": revocation,
        "signature_type": verdict.get("signature_type"),
        # rdp_validate.cs answers these under chain (signature_valid / sign_time / sign_time_verified)
        "content_verified": chain.get("signature_valid") if rdp else verdict.get("content_verified"),
        "is_os_binary": verdict.get("is_os_binary"),
        "timestamped": verdict.get("timestamped"),
        "sign_time": chain.get("sign_time") if rdp else verdict.get("sign_time"),
        "sign_time_verified": chain.get("sign_time_verified") if rdp else verdict.get("sign_time_verified"),
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
        "chain_len": len(chain["chain"]) if isinstance(chain.get("chain"), list) else 0,
        "chain_explicit_distrust": chain.get("explicit_distrust"),
        "chain_valid_at_sign_time": chain.get("valid_at_sign_time"),
        "chain_chains_to_trusted_root": chain.get("chains_to_trusted_root"),
        "chain_builds": chain.get("chain_builds"),
        "chain_revoked": chain.get("revoked"),
        # myatg reports 'unknown' here WITHOUT downgrading status when the responders were unreachable: an hour of
        # dead egress made Records byte-identical to fully checked Valid ones. `revocation` and `status` above now say so;
        # this raw value keeps the why (unknown = unreachable, none = switched off)
        "chain_revocation_checked": chain.get("revocation_checked"),
        "error": verdict.get("error"),
        # timestamper
        "timestamper_subject_cn": tsa.get("subject_cn"),
        "timestamper_tbs_sha256": tsa.get("tbs_sha256"),
        # graveyard
        "graveyard_hit": grave.get("hit"),
        "graveyard_matched_on": grave.get("matched_on"),
        "graveyard_malware": grave.get("malware"),
        "graveyard_malware_type": grave.get("malware_type"),
        # the knobs this verdict was computed under (None = the agent's startup default)
        "param_rev": params.get("rev"),
        "param_scripts": params.get("scripts"),
        # RDP verdicts only (rdp_validate.cs); None on every other verdict
        "rdp_file_name": verdict.get("file") if rdp else None,
        "rdp_signscope_count": verdict.get("signscope_count") if rdp else None,
        "rdp_total_settings": verdict.get("total_settings") if rdp else None,
        "rdp_unsigned_settings": verdict.get("unsigned_settings") if rdp else None,
        "rdp_unsigned_dangerous": verdict.get("unsigned_dangerous") if rdp else None,   # a JSON list (as a string)
    }
    return Record(fields={k: _scalar(v) for k, v in fields.items()})


def summarize_envelope(env: dict) -> dict:
    """The doors' per-job summary of a sealed envelope (pool_manager -> ingress result_summary; the orchestrator's engine pane).

    ``verdict`` is myatg's raw verdict (re-parsed from authenticode_json) and its ``status`` is myatg's own string; ``status`` /
    ``myatg_status`` / ``revocation`` are the engine's Record fields, so a Valid whose revocation went unchecked reads
    ValidRevocationUnchecked on every door. ``warnings`` stays the list of codes; ``warning_details`` adds the message of each warning the engine writes
    (ENGINE_WARNING_CODES), null for any other (an engine_error's infrastructure text is not published)."""
    fields = (env.get("payload") or {}).get("fields") or {}
    raw = fields.get("authenticode_json")
    verdict = None
    if isinstance(raw, str):
        try:
            verdict = json.loads(raw)
        except ValueError:
            verdict = None
    warns = [w for w in env.get("warnings") or [] if isinstance(w, dict)]
    # messages only for the warnings this engine writes: an engine_error's message is the harness's str(exception) from the
    # VM / transport layer (internal addresses, domain names), which a door must not publish
    return {
        "verdict": verdict,
        "status": fields.get("status"),
        "myatg_status": fields.get("myatg_status"),
        "revocation": fields.get("revocation"),
        "param_rev": fields.get("param_rev"),          # the knobs the verdict was computed under (null = agent default)
        "param_scripts": fields.get("param_scripts"),
        "warnings": [w.get("code") for w in warns],
        "warning_details": [{"code": w.get("code"), "message": w.get("message") if w.get("code") in ENGINE_WARNING_CODES else None}
                            for w in warns],
        "envelope_status": env.get("status"),
        # the engine's Record (its own file_sha256, rdp_*, signer_* / chain_* flags) minus the verbatim verdict, which is
        # already under `verdict`: the doors publish only this summary, so a Record-only field must ride here
        "record": {k: v for k, v in fields.items() if k != "authenticode_json"},
    }


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
        """The file type from the content's signature; the extension only names what the content does not (scripts)."""
        try:
            with open(input, "rb") as fh:
                head = fh.read(_SNIFF_BYTES)
                label = _sniff(head)
                if label == _OLE_UNDETERMINED:   # the root directory entry lies past the sniffed bytes: read its CLSID there
                    off = _ole_root_clsid_offset(head)
                    if off is not None:
                        fh.seek(off)
                        clsid = fh.read(16)
                        if len(clsid) == 16:
                            label = "msi" if clsid in _MSI_CLSIDS else "ole"
        except OSError:
            head = b""
            label = None
        if label == _OLE_UNDETERMINED:   # an OLE file whose root entry is past the sniffed bytes: the extension names the kind
            if input.suffix.lower() in (".msi", ".msp", ".mst"):
                return Detection(label="msi", mime=_MIME["msi"], confidence=0.7, source="authenticode:magic+extension")
            return Detection(label="ole", mime=_MIME["ole"], confidence=0.7, source="authenticode:magic")
        if label is not None:
            return Detection(label=label, mime=_MIME[label], confidence=0.95, source="authenticode:magic")
        ext = _EXT_TYPE.get(input.suffix.lower())
        if ext is not None:
            return Detection(label=ext[0], mime=ext[1], confidence=0.5, source="authenticode:extension")
        return Detection(label="binary", mime=_MIME["binary"], confidence=0.2, source="authenticode")

    def precheck(self, limits: Limits) -> str | None:
        """Refuse a job whose per-job parameters name a key or value the agent does not know (sealed ``rejected``, no VM)."""
        try:
            validate_job_params(_JOB_PARAMS.get())
        except ValueError as exc:
            # capped here, not only in detonate(): a harness that calls precheck() seals this reason as a Warning message,
            # which the contract caps at 2000 (repr() of an astral code point is ten characters)
            return f"bad per-job parameter: {exc}"[:2000]
        return None

    def warmup(self, stop_event=None) -> None:
        """Pre-pay the VM-pool boot for the host runner (optional); `stop_event` ends the wait early."""
        get_pool(stop_event=stop_event)

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        # rev/scripts come from the job's params or THIS process's environment and go to the agent as ?rev=/?scripts=; gv (graveyard) is baked into the golden's
        # --serve-http startup and TIER isn't a myatg parameter, so an operator export of either is
        # answered with a warning rather than silently ignored.
        # A bad per-job parameter is refused BEFORE the VM sees the input. precheck() does this on a blastbox whose harness calls
        # it; this repeats it for one that does not (the released harness), so the refusal never depends on the harness version.
        reason = self.precheck(limits)
        if reason is not None:
            return DetonationResult(
                payload=Record(fields={}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[BbWarning(code="precheck_rejected", message=reason[:2000])],
                status="rejected",
            )

        # per-job values (job_params) override the environment; blanks are unset (an agent answers a stray ?rev=++ with its
        # startup default, silently)
        req_params = {_KNOB_PARAM[k]: (v if v in KNOB_VALUES[k].split("|") else _KNOB_FALLBACK_VALUE[k])
                      for k, v in effective_knobs().items() if v}

        # The VM pool provides isolation + recycle; a transport/VM failure raises
        # and the harness writes a clean engine_error envelope.
        verdict = _no_lone_surrogates(get_pool().validate(str(input), params=req_params or None))

        warnings: list[BbWarning] = knob_warnings()
        unforwardable = sorted(k for k in ("AUTHENTICODE_GV", "AUTHENTICODE_TIER") if (os.environ.get(k) or "").strip())
        if unforwardable:
            warnings.append(
                BbWarning(
                    code="param_not_forwarded",
                    message=(
                        "--gv is server-global (baked into the golden's serve startup) and TIER is "
                        "not a myatg parameter; not applied per-job: " + ",".join(unforwardable)
                    ),
                )
            )

        raw = json.dumps(verdict, separators=(",", ":"), default=str)
        (outdir / "authenticode.json").write_text(raw, encoding="utf-8")

        summary = _summary(verdict, req_params)
        # The engine hashes the input it was handed, always: the guest is untrusted (the sample may own the VM), so its
        # file_sha256 never decides which bytes a verdict is attributed to. RDP verdicts and myatg's error skeleton name none.
        h = hashlib.sha256()
        with open(input, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        guest_sha = summary.fields.get("file_sha256")
        summary.fields["file_sha256"] = h.hexdigest()
        if guest_sha is not None and str(guest_sha).lower() != h.hexdigest():
            shown = repr(str(guest_sha)) if re.fullmatch(r"[0-9A-Fa-f]{64}", str(guest_sha)) else "a non-SHA-256 value"
            warnings.append(BbWarning(code="file_sha256_mismatch",
                                      message=f"the agent reported file_sha256 {shown}; the engine hashed the input as "
                                              f"{h.hexdigest()} (recorded)"[:2000]))
            # the verdict is about OTHER bytes (or the guest lied): never attribute its status to the submitted file
            summary.fields["status"] = "UnknownError"
            summary.fields["revocation"] = None
            summary.fields["error"] = "the agent's verdict names other bytes (file_sha256 mismatch); its status is not used"

        if summary.fields.get("rdp_file_name") is not None:   # the --serve-http agent names its upload temp file (myatg_<guid>.rdp)
            summary.fields["rdp_file_name"] = input.name

        myatg_status = verdict.get("status")
        if not isinstance(myatg_status, str) or myatg_status not in MYATG_STATUSES:   # a list/dict status is unhashable
            warnings.append(BbWarning(
                code="status_unrecognized",
                message=f"myatg status {str(myatg_status)[:200]!r} is not one this engine knows ({', '.join(sorted(MYATG_STATUSES))}); passed through"[:2000],
            ))
        # Embed the verbatim verdict so the full chain survives in the envelope,
        # not only in the artifact (the ClippyShot clippyshot_metadata pattern).
        summary.fields["authenticode_json"] = raw

        # A graveyard hit is a strong malicious signal — surface it as a warning.
        grave = _obj(verdict.get("graveyard"))
        if grave.get("hit"):
            warnings.append(
                BbWarning(
                    code="graveyard_hit",
                    message=(
                        f"signing cert in graveyard (matched_on={grave.get('matched_on')}, "
                        f"malware={grave.get('malware')})"
                    )[:2000],   # both values come from the guest's answer: the contract caps a message at 2000
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

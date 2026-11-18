# winval_blastbox — the blastbox `authenticode` engine

Wraps the **myatg** Windows validator as a blastbox engine (win-validator design §3a,
P2). Given a PE/MSI/CAB/script/RDP file it returns a blastbox **sealed envelope** whose
payload is the myatg signature/cert-graveyard verdict.

## Why this engine is host-resident (not a container worker)

ClippyShot/RedTusk engines run *inside* a disposable Linux container the blastbox
dispatcher `docker run`s. This engine's disposable worker is a **Windows VM** (libvirt
overlay clone off the golden, driven over HTTP by `vm_pool.py`) — it can't run
Python/blastbox. So the engine runs **host-side** on the libvirt host (toolz3) and the VM
*is* the sandbox. It is driven by `host_runner.HostRunner`, which calls
`blastbox.worker.harness.run_detonation` in-process per job — the same seal/confine/validate
path the container harness uses, minus the container-only egress barrier in `harness.main`.

```
HostRunner.validate(file)
  -> run_detonation(AuthenticodeEngine, ...)        # blastbox harness, in-process
       -> AuthenticodeEngine.detonate()
            -> WarmVmPool.validate(file, params)    # blastbox WarmPool over libvirt workers
                 -> POST /validate?name=..[&rev=..&scripts=..]  ->  myatg.exe --serve-http
            -> Record summary + embedded JSON + authenticode.json artifact
       -> seal_envelope -> metadata.json            # trusted, hashes recomputed from disk
```

## Files

| File | Role |
|------|------|
| `engine.py` | `AuthenticodeEngine` — the blastbox `Engine`; maps myatg JSON → `DetonationResult`. Module-level warm VM-pool singleton (`get_pool`/`warmup`/`shutdown_pool`). |
| `host_runner.py` | `HostRunner` — in-process bridge that keeps the pool warm and drives each job through `run_detonation`. CLI: `python -m winval_blastbox.host_runner <file>` — exit 0 for any verdict, 1 when the sealed envelope is an `engine_error` (VM or transport failure), 2 for a usage or configuration error (no file, not a file, a bad `BLASTBOX_*` value; one line on stderr), 143 when a SIGTERM ended it before a verdict (empty stdout). |
| `vm_pool.py` | `WarmVmPool` — blastbox `WarmPool` over `LibvirtVmRuntime` (overlay-clone workers off the golden, recycle-after-N). `agent_validate` is the HTTP client. The guest agent is **`myatg.exe --serve-http`**, baked into the golden as the ONSTART task (`NT AUTHORITY\NETWORK SERVICE`, LIMITED) — so there is no PowerShell shim anymore. |
| `orchestrator.py` | **P3** — thin FastAPI fan-out (`POST /scan`, `GET /scan/{id}`, `GET /cert/{tbs}`, `GET /healthz`). Warms the pool at startup, runs engines off-request-path via a bounded executor, returns each engine's verdict side-by-side (components, not an opinion). |

## Orchestrator (P3)

```sh
# on the libvirt host (toolz3); warms the VM pool at startup
uvicorn winval_blastbox.orchestrator:app --host 127.0.0.1 --port 8099

curl -F file=@suspect.dll 'http://127.0.0.1:8099/scan'        # -> {job_id, status:queued}
curl http://127.0.0.1:8099/scan/<job_id>                       # -> per-engine verdicts
```

`POST /scan` accepts a file + optional `engines=authenticode,...` (default `authenticode`);
unbuilt engines (`ember-legacy`/`ember-2024`, P4) return `status:"unavailable"`. The
authenticode result is the parsed myatg verdict (status / signer / chain / graveyard) plus
the sealed `authenticode.json` artifact reference. `GET /cert/{tbs_sha256}` returns every scanned
file (the orchestrator's own in-memory store) whose signer or chain carries that cert. The ingress's
`/cert/{tbs}` is the bounded one — see `deploy/README.md`.

## Output (payload `Record` fields)

`schema_version` (`authenticode-record/2`), `file_sha256, status, myatg_status, revocation, signature_type, content_verified, is_os_binary, timestamped,
sign_time, sign_time_verified`, `signer_*` (subject/issuer CN, serial, thumbprint,
sha1/sha256/tbs_sha256 fingerprints, eku_codesigning, self_signed, validity window),
`chain_len, chain_explicit_distrust, chain_valid_at_sign_time`, `timestamper_*`,
`graveyard_{hit,matched_on,malware,malware_type}`, plus the verbatim verdict embedded as
`authenticode_json` and written to the `authenticode.json` artifact; `param_rev, param_scripts` (the knobs
the verdict was computed under, null = agent default); and on RDP verdicts `rdp_file_name,
rdp_signscope_count, rdp_total_settings, rdp_unsigned_settings, rdp_unsigned_dangerous` (a JSON list).
`file_sha256` is the engine's own hash of the input when myatg names none (RDP, error skeleton).
A graveyard hit emits a `graveyard_hit` warning; a myatg status outside the known set
(`engine.MYATG_STATUSES`) is passed through with a `status_unrecognized` warning. The envelope's
`detected` type comes from the content's signature (PE, CAB, PKCS#7 catalog, RDP text; an OLE compound
file is `msi` when its root-entry CLSID is the Windows Installer one, else `ole`), the extension only for
scripts.

Both doors' job summaries (`result_summary` on the ingress, the `authenticode` pane on the orchestrator)
carry myatg's raw `verdict` plus the engine's `status`, `myatg_status`, `revocation`, the knobs applied
(`param_rev`, `param_scripts`), the warning codes (`warnings`) and each warning with its message
(`warning_details`). On the orchestrator pane the engine's status is `verdict_status`, since the pane's
own `status` is its lifecycle (`running`/`done`/`error`). `/jobs` lists `verdict` as the engine's status
with `myatg_status` and `revocation` beside it; an ingress row written before this summary existed gets
the same rule applied to its stored raw verdict.

`revocation` is the revocation half of the verdict, explicit: `checked_good` (responders or CRL cache
answered, not revoked), `revoked`, `unchecked` (`chain_revocation_checked` is `unknown` = responders
unreachable, or `none` = `AUTHENTICODE_REV=none`), `error` (a chain whose answer is missing or outside
myatg's vocabulary; treated as not checked), or null (no chain evaluated: NotSigned, error skeleton). A
`Valid` with no chain (myatg's `scripts=ps` branch) is `unchecked`.
myatg answers `Valid` in the unchecked case, so `status` never repeats a bare `Valid` there: it is
`ValidRevocationUnchecked` unless `revocation == "checked_good"` (`Revoked` if the chain is revoked).
Every other status passes through; myatg's own string is always `myatg_status`.

## Config (env)

| Var | Meaning |
|-----|---------|
| `AUTHENTICODE_POOL_SIZE` | warm VM workers (default 2) |
| `AUTHENTICODE_GOLDEN_BASE` | golden qcow2 (default `/dev/shm/golden-base.qcow2`) |
| `MYATG_SRC` | (build only) dir holding the myatg `*.cs` sources to compile in-guest — a myatg checkout; default `../myatg` beside this repo |

Per-job parameters: both doors' `POST /scan` take optional multipart form fields `rev` (`online|offline|none`)
and `scripts` (`ps|native`), stored as the job's `params` (`AUTHENTICODE_REV` / `AUTHENTICODE_SCRIPTS`). Anything
else is a 400 before the upload is spooled, and the engine re-checks them (a bad value in the job store seals
`rejected`, recorded as a failed job, without a VM). A job's value overrides the engine process's environment for
that job only; blank falls back to it. The values a verdict was computed under are `param_rev` / `param_scripts`.
`AUTHENTICODE_GV` and `AUTHENTICODE_TIER` are read by nothing (the graveyard knob is `GOLDEN_GRAVEYARD`, baked into the
golden's serve startup; TIER is not a myatg parameter): exporting either into the engine process puts an honest
`param_not_forwarded` warning on every verdict, and a request cannot set them.

## Status

P2 engine: **built + validated end-to-end on toolz3** (engine → myatg VM pool → sealed
envelope; 4/4 verdicts match the corpus `results.jsonl` reference). myatg.exe is baked into
the golden as the `--serve-http` ONSTART agent (no per-boot compile); `rev`/`scripts` default to the engine
process's setting (above) and a scan request may set them per job (`rev`/`scripts` form fields). Follow-ups: the P4 `ember-legacy`/`ember-2024` ML engines (the orchestrator
already fans out to them).

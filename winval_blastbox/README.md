# winval_blastbox — the blastbox `authenticode` engine

Wraps the **myatg** Windows validator as a blastbox engine (win-validator design §3a,
P2). Given a PE/MSI/CAB/script/RDP file it returns a blastbox **sealed envelope** whose
payload is the myatg signature/cert-graveyard verdict.

## Why this engine is host-resident (not a container worker)

ClippyShot/RedTusk engines run *inside* a disposable Linux container the blastbox
dispatcher `docker run`s. This engine's disposable worker is a **Windows VM** (libvirt
overlay clone off the golden, driven over TCP by `pool.py`) — it can't run
Python/blastbox. So the engine runs **host-side** on the libvirt host (toolz3) and the VM
*is* the sandbox. It is driven by `host_runner.HostRunner`, which calls
`blastbox.worker.harness.run_detonation` in-process per job — the same seal/confine/validate
path the container harness uses, minus the container-only egress barrier in `harness.main`.

```
HostRunner.validate(file)
  -> run_detonation(AuthenticodeEngine, ...)        # blastbox harness, in-process
       -> AuthenticodeEngine.detonate()
            -> WorkerPool.validate(file)            # round-robin warm VM pool
                 -> TCP -> guest-agent-myatg.ps1 -> myatg.exe   # <-- "this tool"
            -> Record summary + embedded JSON + authenticode.json artifact
       -> seal_envelope -> metadata.json            # trusted, hashes recomputed from disk
```

## Files

| File | Role |
|------|------|
| `engine.py` | `AuthenticodeEngine` — the blastbox `Engine`; maps myatg JSON → `DetonationResult`. Module-level warm VM-pool singleton (`get_pool`/`warmup`/`shutdown_pool`). |
| `host_runner.py` | `HostRunner` — in-process bridge that keeps the pool warm and drives each job through `run_detonation`. CLI: `python -m winval_blastbox.host_runner <file>`. |
| `pool.py` | `AuthenticodeWorker` / `WorkerPool` — libvirt overlay-clone workers off the golden, TCP transport, recycle-after-N. `start_agent` serves **myatg.exe**. |
| `guest-agent-myatg.ps1` | Windows guest agent (now **baked into the golden** as the ONSTART task, pre-compiled): serves the length-prefixed TCP protocol by shelling `myatg.exe <file> --gv <csv>`. |
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
the sealed `authenticode.json` artifact reference. `GET /cert/{tbs_sha256}` returns every
scanned file whose signer or chain carries that cert.

## Output (payload `Record` fields)

`file_sha256, status, signature_type, content_verified, is_os_binary, timestamped,
sign_time, sign_time_verified`, `signer_*` (subject/issuer CN, serial, thumbprint,
sha1/sha256/tbs_sha256 fingerprints, eku_codesigning, self_signed, validity window),
`chain_len, chain_explicit_distrust, chain_valid_at_sign_time`, `timestamper_*`,
`graveyard_{hit,matched_on,malware,malware_type}`, plus the verbatim verdict embedded as
`authenticode_json` and written to the `authenticode.json` artifact. A graveyard hit emits
a `graveyard_hit` warning.

## Config (env)

| Var | Meaning |
|-----|---------|
| `AUTHENTICODE_POOL_SIZE` | warm VM workers (default 2) |
| `AUTHENTICODE_GOLDEN_BASE` | golden qcow2 (default `/dev/shm/golden-base.qcow2`) |
| `AUTHENTICODE_MYATG_SRC` | dir holding `myatg.cs`/`rdp_validate.cs` to stage (default `/home/coz/winval`) |

Per-job param keys (`AUTHENTICODE_REV/SCRIPTS/GV/TIER`) are declared in `engine.PARAM_KEYS`
for the orchestrator allowlist (`BLASTBOX_ENGINE_AUTHENTICODE_PARAM_KEYS`) but are **not yet
plumbed to the guest agent** (transport is `[filename][bytes]` only) — a requested override
surfaces a `param_not_forwarded` warning. Forwarding them is a follow-up.

## Status

P2 engine: **built + validated end-to-end on toolz3** (engine → myatg VM pool → sealed
envelope; 4/4 verdicts match the corpus `results.jsonl` reference). Follow-ups: bake
myatg.exe + the myatg agent into the golden (drop the per-boot compile + make it the
default); plumb per-job params to the guest agent; P3 orchestrator FastAPI fan-out.

"""P3 orchestrator — thin FastAPI fan-out over the validation engines.

Per the win-validator design §8: accept a file, fan out to the selected engines, and
return a job id; the verdict is **components, not an opinion** (each engine's result is
returned side-by-side — the caller decides). Built on the engine + host runner from this
package; the `authenticode` engine is host-resident (drives a Windows-VM worker pool over
TCP), so the orchestrator calls its `HostRunner` in-process rather than the blastbox
container dispatcher. EMBER engines (P4) slot into `ENGINES` later with the same shape.

Endpoints:
  POST /scan        multipart file [+ engines=authenticode,...]   -> {job_id, status}
  GET  /scan/{id}                                                  -> {status, engines:{...}}
  GET  /cert/{tbs_sha256}                                          -> verdicts seen for a cert
  GET  /healthz                                                    -> pool readiness

Run on the libvirt host (toolz3):
    uvicorn winval_blastbox.orchestrator:app --host 127.0.0.1 --port 8099
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

from .host_runner import HostRunner

# Engine registry. Each entry: name -> callable(path) -> verdict dict. authenticode is the
# only built engine; ember-legacy / ember-2024 (P4) register here later with the same shape.
# Populated at startup (lifespan) so the VM pool warms once.
ENGINES: dict[str, Callable[[str], dict]] = {}

DEFAULT_ENGINES = ("authenticode",)


def _authenticode_verdict(env: dict) -> dict:
    """Extract the myatg verdict (components, not opinion) from a sealed envelope.

    The engine embeds the verbatim myatg JSON as the ``authenticode_json`` payload field
    and writes it to the ``authenticode.json`` artifact; surface the parsed verdict plus the
    sealed artifact reference.
    """
    fields = (env.get("payload") or {}).get("fields") or {}
    raw = fields.get("authenticode_json")
    verdict = None
    if isinstance(raw, str):
        try:
            verdict = json.loads(raw)
        except ValueError:
            verdict = None
    return {
        "verdict": verdict,
        "warnings": [w.get("code") for w in env.get("warnings") or []],
        "artifact": next((a for a in env.get("artifacts") or [] if a.get("id") == "authenticode"), None),
        "envelope_status": env.get("status"),
    }


class JobStore:
    """In-memory job store + a bounded executor that drives the engines off the request path."""

    def __init__(self, max_workers: int, max_jobs: int = 2000) -> None:
        self._jobs: dict[str, dict] = {}
        self._max_jobs = max_jobs  # bound this in-memory store (non-persistent; see PR follow-up)
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")

    def create(self, filename: str, engines: list[str]) -> str:
        jid = uuid.uuid4().hex
        with self._lock:
            self._jobs[jid] = {
                "job_id": jid,
                "status": "queued",
                "filename": filename,
                "engines": {e: {"status": "queued"} for e in engines},
            }
            # evict oldest (insertion-ordered) beyond the cap so a long-running orchestrator
            # doesn't grow _jobs unbounded per scan
            while len(self._jobs) > self._max_jobs:
                self._jobs.pop(next(iter(self._jobs)))
        return jid

    def get(self, jid: str) -> dict | None:
        with self._lock:
            j = self._jobs.get(jid)
            return json.loads(json.dumps(j)) if j else None

    def _update(self, jid: str, **kw: Any) -> None:
        with self._lock:
            self._jobs[jid].update(kw)

    def _update_engine(self, jid: str, engine: str, value: dict) -> None:
        with self._lock:
            self._jobs[jid]["engines"][engine] = value

    def submit(self, jid: str, path: str, engines: list[str]) -> None:
        self._pool.submit(self._run, jid, path, engines)

    def _run(self, jid: str, path: str, engines: list[str]) -> None:
        self._update(jid, status="running")
        try:
            for e in engines:
                runner = ENGINES.get(e)
                if runner is None:
                    self._update_engine(jid, e, {"status": "unavailable", "reason": "engine not registered"})
                    continue
                try:
                    self._update_engine(jid, e, {"status": "running"})
                    result = runner(path)
                    # a sealed engine_error envelope (VM/transport failure) must surface as 'error',
                    # not a 'done' job with a silently-null verdict indistinguishable from success.
                    e_status = "error" if result.get("envelope_status") == "engine_error" else "done"
                    self._update_engine(jid, e, {"status": e_status, **result})
                except Exception as exc:  # noqa: BLE001 — one engine failing must not sink the job
                    self._update_engine(jid, e, {"status": "error", "error": type(exc).__name__})
            self._update(jid, status="done")
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def list_jobs(self, limit: int = 100) -> list[dict]:
        """Recent scans (newest first) with just the headline status — for the UI list."""
        with self._lock:
            jobs = list(self._jobs.values())
        out = []
        for j in reversed(jobs[-limit:]):
            ac = (j.get("engines") or {}).get("authenticode") or {}
            v = ac.get("verdict") or {}
            out.append({
                "job_id": j["job_id"], "filename": j["filename"], "status": j["status"],
                "verdict": v.get("status"), "signature_type": v.get("signature_type"),
                "graveyard_hit": "graveyard_hit" in (ac.get("warnings") or []),
            })
        return out

    def cert_lookup(self, tbs_sha256: str) -> list[dict]:
        """Cert-centric view: every job whose authenticode signer/chain carries this tbs."""
        tbs = tbs_sha256.lower()
        hits = []
        with self._lock:
            for j in self._jobs.values():
                ac = (j.get("engines") or {}).get("authenticode") or {}
                v = ac.get("verdict") or {}
                certs = []
                s = v.get("signer") or {}
                if s.get("tbs_sha256"):
                    certs.append(s["tbs_sha256"].lower())
                for c in (v.get("chain") or {}).get("chain") or []:
                    if c.get("tbs_sha256"):
                        certs.append(c["tbs_sha256"].lower())
                if tbs in certs:
                    hits.append({"job_id": j["job_id"], "filename": j["filename"], "status": v.get("status")})
        return hits


_store: JobStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store
    pool_size = int(os.environ.get("AUTHENTICODE_POOL_SIZE", "2"))
    _store = JobStore(max_workers=pool_size)
    if os.environ.get("ORCHESTRATOR_WARM", "1").lower() in ("1", "true", "yes"):
        runner = HostRunner()
        runner.warmup()  # boot the VM pool once
        ENGINES["authenticode"] = lambda p: _authenticode_verdict(runner.validate(p))
    yield
    # shutdown: tear the VM pool down cleanly
    from .engine import shutdown_pool

    shutdown_pool()


app = FastAPI(title="win-validator orchestrator", lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "engines": sorted(ENGINES), "pool_size": int(os.environ.get("AUTHENTICODE_POOL_SIZE", "2"))}


@app.post("/scan", status_code=202)
async def scan(file: UploadFile = File(...), engines: str = Form("")) -> dict:
    if _store is None:
        raise HTTPException(503, "orchestrator not ready")
    sel = [e.strip() for e in engines.split(",") if e.strip()] or list(DEFAULT_ENGINES)
    # Stream the upload to a private temp file in chunks with a hard size cap, so a huge (or
    # slow-loris many-concurrent) upload can't be buffered whole into RAM and OOM the service.
    # Clean up the temp file on any failure before the job is queued (only _run unlinks otherwise).
    max_bytes = int(os.environ.get("AUTHENTICODE_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
    fd, path = tempfile.mkstemp(prefix="scan-", suffix="-" + Path(file.filename or "input").name)
    try:
        written = 0
        with os.fdopen(fd, "wb") as f:
            while chunk := await file.read(1 << 20):  # 1 MiB chunks
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(413, f"upload exceeds {max_bytes} bytes")
                f.write(chunk)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    jid = _store.create(file.filename or "input", sel)
    _store.submit(jid, path, sel)
    return {"job_id": jid, "status": "queued", "engines": sel}


@app.get("/scan/{job_id}")
def scan_status(job_id: str) -> dict:
    if _store is None:
        raise HTTPException(503, "orchestrator not ready")
    j = _store.get(job_id)
    if j is None:
        raise HTTPException(404, "job not found")
    return j


@app.get("/cert/{tbs_sha256}")
def cert(tbs_sha256: str) -> dict:
    if _store is None:
        raise HTTPException(503, "orchestrator not ready")
    return {"tbs_sha256": tbs_sha256, "seen_in": _store.cert_lookup(tbs_sha256)}


@app.get("/jobs")
def jobs(limit: int = 100) -> dict:
    if _store is None:
        raise HTTPException(503, "orchestrator not ready")
    return {"jobs": _store.list_jobs(min(max(limit, 1), 500))}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>win-validator</title>
<style>
  :root{--bg:#0f1419;--panel:#1a212b;--line:#2b3543;--fg:#e6edf3;--mut:#8b98a9;--acc:#4493f8}
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
  header{background:#0b0f14;border-bottom:1px solid var(--line);padding:12px 20px;display:flex;align-items:baseline;gap:12px}
  header h1{font-size:17px;margin:0;letter-spacing:.3px}
  header .sub{color:var(--mut);font-size:12px}
  .wrap{display:grid;grid-template-columns:340px 1fr;gap:16px;padding:16px;max-width:1200px;margin:0 auto}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
  .drop{border:1.5px dashed var(--line);border-radius:8px;padding:22px;text-align:center;color:var(--mut);cursor:pointer}
  .drop.over{border-color:var(--acc);color:var(--fg)}
  button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:8px 14px;font-weight:600;cursor:pointer}
  button:disabled{opacity:.5;cursor:default}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);margin:18px 0 8px}
  .job{padding:8px 10px;border:1px solid var(--line);border-radius:6px;margin-bottom:6px;cursor:pointer;display:flex;justify-content:space-between;gap:8px;align-items:center}
  .job:hover{border-color:var(--acc)}
  .job .fn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}
  .Valid{background:#1c3a25;color:#5ee08a} .Revoked,.Distrusted{background:#3a1c1f;color:#ff7b7b}
  .UntrustedRoot,.HashMismatch,.Expired,.NotYetValid,.UnknownError,.ContentUnverified{background:#3a311c;color:#ffce6b}
  .NotSigned,.queued,.running,.unknown{background:#2b3543;color:#9fb0c3}
  table{width:100%;border-collapse:collapse} td{padding:4px 8px;vertical-align:top;border-top:1px solid var(--line)}
  td.k{color:var(--mut);width:160px;white-space:nowrap} .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
  .chain{margin:4px 0;padding-left:0;list-style:none}
  .chain li{padding:6px 10px;border-left:2px solid var(--line);margin-left:6px}
  .flag{font-size:11px;padding:1px 7px;border-radius:4px;margin-right:5px;background:#2b3543;color:#9fb0c3}
  .flag.ok{background:#1c3a25;color:#5ee08a} .flag.bad{background:#3a1c1f;color:#ff7b7b}
  .gv{border:1px solid #5a2b2b;background:#241416;border-radius:6px;padding:10px;margin:8px 0}
  a{color:var(--acc);cursor:pointer;text-decoration:none} a:hover{text-decoration:underline}
  .muted{color:var(--mut)} .empty{color:var(--mut);text-align:center;padding:30px}
</style></head><body>
<header><h1>win-validator</h1><span class="sub">Authenticode / cert-graveyard trust verdicts</span></header>
<div class="wrap">
  <div>
    <div class="panel">
      <div id="drop" class="drop">Drop a file or click to choose<br><span class="muted">PE / DLL / SYS / MSI / CAB / script / RDP</span></div>
      <input id="file" type="file" style="display:none">
      <div style="margin-top:10px;display:flex;justify-content:space-between;align-items:center">
        <span id="fname" class="muted">no file</span>
        <button id="go" disabled>Validate</button>
      </div>
    </div>
    <h2>Recent scans</h2>
    <div id="list"><div class="empty">none yet</div></div>
  </div>
  <div id="detail" class="panel"><div class="empty">Submit a file or pick a scan to see its verdict.</div></div>
</div>
<script>
const $=s=>document.querySelector(s), esc=s=>(s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const pill=(s,extra='')=>`<span class="pill ${esc(s||'unknown')}">${esc(s||'—')}</span>${extra}`;
let chosen=null, poll=null;
async function jget(u){const r=await fetch(u);if(!r.ok)throw new Error(r.status);return r.json();}
function pick(f){chosen=f;$('#fname').textContent=f?f.name:'no file';$('#go').disabled=!f;}
$('#file').onchange=e=>pick(e.target.files[0]);
$('#drop').onclick=()=>$('#file').click();
['dragover','dragleave','drop'].forEach(ev=>$('#drop').addEventListener(ev,e=>{e.preventDefault();
  $('#drop').classList.toggle('over',ev==='dragover');if(ev==='drop'&&e.dataTransfer.files[0])pick(e.dataTransfer.files[0]);}));
$('#go').onclick=async()=>{if(!chosen)return;$('#go').disabled=true;
  const fd=new FormData();fd.append('file',chosen);
  try{const r=await(await fetch('/scan',{method:'POST',body:fd})).json();watch(r.job_id);await refresh();}
  catch(e){$('#detail').innerHTML='<div class="empty">submit failed: '+esc(e)+'</div>';}
  $('#go').disabled=false;};
function watch(id){clearInterval(poll);const tick=async()=>{const j=await jget('/scan/'+id);render(j);
  if(j.status==='done'||j.status==='error'){clearInterval(poll);refresh();}};tick();poll=setInterval(tick,1200);}
async function refresh(){try{const {jobs}=await jget('/jobs?limit=80');
  $('#list').innerHTML=jobs.length?jobs.map(j=>`<div class="job" onclick="watch('${j.job_id}')">
    <span class="fn" title="${esc(j.filename)}">${esc(j.filename)}</span>
    ${pill(j.verdict||j.status)}${j.graveyard_hit?' <span class="flag bad">graveyard</span>':''}</div>`).join('')
    :'<div class="empty">none yet</div>';}catch(e){}}
function flags(c){const f=[];const F=(ok,t,bad)=>f.push(`<span class="flag ${ok?'ok':(bad?'bad':'')}">${t}</span>`);
  if(c.chains_to_trusted_root!=null)F(c.chains_to_trusted_root,'trusted root',!c.chains_to_trusted_root);
  if(c.revoked)F(false,'revoked',true); if(c.explicit_distrust)F(false,'distrusted',true);
  if(c.valid_at_sign_time!=null)F(c.valid_at_sign_time,'valid@sign',!c.valid_at_sign_time);
  if(c.revocation_checked)f.push(`<span class="flag">rev: ${esc(c.revocation_checked)}</span>`);
  return f.join('');}
function certRow(c){const cn=c.subject_cn||c.subject||'—';
  return `<li><b>${esc(cn)}</b> ${c.self_signed?'<span class="flag bad">self-signed</span>':''}
    <div class="muted">issuer: ${esc(c.issuer_cn||c.issuer||'—')}${c.not_after?' · expires '+esc(c.not_after.slice(0,10)):''}</div>
    ${c.tbs_sha256?`<div class="mono"><a onclick="cert('${c.tbs_sha256}')">${esc(c.tbs_sha256)}</a></div>`:''}</li>`;}
function render(j){const ac=(j.engines||{}).authenticode||{}, v=ac.verdict, w=ac.warnings||[];
  if(ac.status==='queued'||ac.status==='running'||j.status==='queued'||j.status==='running'){
    $('#detail').innerHTML=`<h3>${esc(j.filename)}</h3>${pill(ac.status||j.status)} <span class="muted">validating…</span>`;return;}
  if(!v){$('#detail').innerHTML=`<h3>${esc(j.filename)}</h3>${pill(ac.status||'error')}
    <div class="muted" style="margin-top:8px">${esc((ac.error)||ac.reason||'no verdict')}</div>`;return;}
  const s=v.signer||{}, ch=v.chain||{}, gv=v.graveyard||{};
  let h=`<h3>${esc(j.filename)}</h3><div style="margin:6px 0 14px">${pill(v.status)}
    <span class="flag">${esc(v.signature_type)}</span>${v.is_os_binary?'<span class="flag ok">OS binary</span>':''}
    ${v.content_verified===false?'<span class="flag bad">content unverified</span>':''}
    ${w.map(x=>`<span class="flag bad">${esc(x)}</span>`).join('')}</div>`;
  if(gv&&(gv.hit||gv.malware)) h+=`<div class="gv"><b>cert-graveyard hit</b> ${gv.matched_on?'· matched on '+esc(gv.matched_on):''}
    <div>${esc(gv.malware||gv.malware_type||'')} ${gv.malware_notes?'— '+esc(gv.malware_notes):''}</div></div>`;
  h+='<table>';
  const row=(k,val)=>{if(val==null||val==='')return;h+=`<tr><td class="k">${k}</td><td>${val}</td></tr>`;};
  row('file sha256',`<span class="mono">${esc(v.file_sha256)}</span>`);
  if(s.subject||s.subject_cn) row('signer',`${esc(s.subject_cn||s.subject)}<div class="muted">issuer ${esc(s.issuer_cn||s.issuer||'—')}</div>
    <div class="muted">${esc((s.not_before||'').slice(0,10))} → ${esc((s.not_after||'').slice(0,10))}</div>`);
  if(s.tbs_sha256) row('signer cert',`<span class="mono"><a onclick="cert('${s.tbs_sha256}')">${esc(s.tbs_sha256)}</a></span>`);
  if(ch.chain&&ch.chain.length) row('chain ('+ch.chain.length+')',`<div>${flags(ch)}</div><ul class="chain">${ch.chain.map(certRow).join('')}</ul>`);
  else if(Object.keys(ch).length) row('chain',flags(ch));
  if(v.timestamped) row('timestamp',`${esc((v.sign_time||'').replace('T',' ').slice(0,19))} ${v.sign_time_verified?'<span class="flag ok">verified</span>':'<span class="flag">unverified</span>'}<div class="muted">${esc((v.timestamper||{}).subject_cn||'')}</div>`);
  row('error',v.error?`<span class="mono">${esc(v.error)}</span>`:'');
  if(ac.error) row('engine',`<span class="flag bad">${esc(ac.error)}</span>`);
  h+='</table>';
  $('#detail').innerHTML=h;}
async function cert(tbs){const r=await jget('/cert/'+tbs);
  $('#detail').innerHTML=`<h3>cert <span class="mono">${esc(tbs)}</span></h3>
    <p class="muted">files signed by / chaining to this cert (${r.seen_in.length}):</p>
    ${r.seen_in.length?r.seen_in.map(x=>`<div class="job" onclick="watch('${x.job_id}')"><span class="fn">${esc(x.filename)}</span>${pill(x.status)}</div>`).join(''):'<div class="empty">none in this session</div>'}`;}
refresh();setInterval(refresh,5000);
</script></body></html>"""

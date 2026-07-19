"""win-validator INGRESS — the untrusted-facing half of the split.

This is the api tier, mirroring blastbox.host's ``serve``: it accepts uploads + serves the UI,
spools each input ONCE to a shared ``job_root`` dir, and writes a ``queued`` Job to a shared
JobStore. It does NOT touch libvirt, iptables, or the worker network — its entire interface is the
JobStore + the job_root volume, so it runs unprivileged (a container) and a web-stack compromise is
contained. The privileged ``pool_manager`` (libvirt + egress + the VM workers) claims the queued
jobs across that boundary and writes the verdict back as the Job's ``result_summary``.

    BLASTBOX_DATABASE_URL   shared JobStore (sqlite:///… | postgresql://… | redis://…)
    WINVAL_JOB_ROOT         shared dir for spooled inputs (default /var/lib/winval/jobs)

Run:  uvicorn winval_blastbox.ingress:app --host 0.0.0.0 --port 8099
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.factory import build_job_store_from_env
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

JOB_ROOT = Path(os.environ.get("WINVAL_JOB_ROOT", "/var/lib/winval/jobs"))
MAX_BYTES = int(os.environ.get("AUTHENTICODE_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
ENGINE = "authenticode"

_store = build_job_store_from_env()
app = FastAPI(title="win-validator ingress")


def _verdict(job: Job) -> dict:
    """The myatg verdict the pool_manager stashed in result_summary (or {})."""
    return (job.result_summary or {}).get("verdict") or {}


def _warnings(job: Job) -> list[str]:
    return (job.result_summary or {}).get("warnings") or []


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "store": type(_store).__name__,
            "queued": _store.count(JobStatus.QUEUED), "job_root": str(JOB_ROOT)}


@app.post("/scan", status_code=202)
async def scan(file: UploadFile = File(...)) -> dict:
    job = Job.new(engine=ENGINE, filename=Path(file.filename or "input").name)
    job.result_dir = str(JOB_ROOT / job.job_id)
    indir = Path(job.result_dir) / "input"
    indir.mkdir(parents=True, exist_ok=True)
    path = indir / job.filename
    # Stream to the shared volume in chunks with a hard size cap (no whole-file RAM buffering),
    # hashing as we go; clean up the spool on any failure before the job is created.
    h = hashlib.sha256()
    try:
        written = 0
        with open(path, "wb") as f:
            while chunk := await file.read(1 << 20):
                written += len(chunk)
                if written > MAX_BYTES:
                    raise HTTPException(413, f"upload exceeds {MAX_BYTES} bytes")
                h.update(chunk)
                f.write(chunk)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    job.input_sha256 = h.hexdigest()
    _store.create(job)
    return {"job_id": job.job_id, "status": job.status.value}


@app.get("/scan/{job_id}")
def scan_status(job_id: str) -> dict:
    job = _store.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job.to_public_dict()


@app.get("/jobs")
def jobs(limit: int = 80) -> dict:
    out = []
    for j in _store.list(limit=min(max(limit, 1), 500), newest_first=True):
        v = _verdict(j)
        out.append({"job_id": j.job_id, "filename": j.filename, "status": j.status.value,
                    "verdict": v.get("status"), "signature_type": v.get("signature_type"),
                    "graveyard_hit": "graveyard_hit" in _warnings(j)})
    return {"jobs": out}


@app.get("/cert/{tbs_sha256}")
def cert(tbs_sha256: str) -> dict:
    tbs = tbs_sha256.lower()
    hits = []
    for j in _store.list():  # whole set; fine for the session-scale histories this serves
        v = _verdict(j)
        certs = []
        s = v.get("signer") or {}
        if s.get("tbs_sha256"):
            certs.append(s["tbs_sha256"].lower())
        for c in (v.get("chain") or {}).get("chain") or []:
            if c.get("tbs_sha256"):
                certs.append(c["tbs_sha256"].lower())
        if tbs in certs:
            hits.append({"job_id": j.job_id, "filename": j.filename, "status": v.get("status")})
    return {"tbs_sha256": tbs_sha256, "seen_in": hits}


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
  header h1{font-size:17px;margin:0;letter-spacing:.3px} header .sub{color:var(--mut);font-size:12px}
  .wrap{display:grid;grid-template-columns:340px 1fr;gap:16px;padding:16px;max-width:1200px;margin:0 auto}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
  .drop{border:1.5px dashed var(--line);border-radius:8px;padding:22px;text-align:center;color:var(--mut);cursor:pointer}
  .drop.over{border-color:var(--acc);color:var(--fg)}
  button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:8px 14px;font-weight:600;cursor:pointer}
  button:disabled{opacity:.5;cursor:default}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);margin:18px 0 8px}
  .job{padding:8px 10px;border:1px solid var(--line);border-radius:6px;margin-bottom:6px;cursor:pointer;display:flex;justify-content:space-between;gap:8px;align-items:center}
  .job:hover{border-color:var(--acc)} .job .fn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}
  .Valid{background:#1c3a25;color:#5ee08a} .Revoked,.Distrusted,.failed{background:#3a1c1f;color:#ff7b7b}
  .UntrustedRoot,.HashMismatch,.Expired,.NotYetValid,.UnknownError,.ContentUnverified{background:#3a311c;color:#ffce6b}
  .NotSigned,.queued,.running,.unknown,.done{background:#2b3543;color:#9fb0c3}
  table{width:100%;border-collapse:collapse} td{padding:4px 8px;vertical-align:top;border-top:1px solid var(--line)}
  td.k{color:var(--mut);width:160px;white-space:nowrap} .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
  .chain{margin:4px 0;padding-left:0;list-style:none} .chain li{padding:6px 10px;border-left:2px solid var(--line);margin-left:6px}
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
        <span id="fname" class="muted">no file</span><button id="go" disabled>Validate</button>
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
$('#file').onchange=e=>pick(e.target.files[0]); $('#drop').onclick=()=>$('#file').click();
['dragover','dragleave','drop'].forEach(ev=>$('#drop').addEventListener(ev,e=>{e.preventDefault();
  $('#drop').classList.toggle('over',ev==='dragover');if(ev==='drop'&&e.dataTransfer.files[0])pick(e.dataTransfer.files[0]);}));
$('#go').onclick=async()=>{if(!chosen)return;$('#go').disabled=true;
  const fd=new FormData();fd.append('file',chosen);
  try{const r=await(await fetch('/scan',{method:'POST',body:fd})).json();watch(r.job_id);await refresh();}
  catch(e){$('#detail').innerHTML='<div class="empty">submit failed: '+esc(e)+'</div>';}
  $('#go').disabled=false;};
function watch(id){clearInterval(poll);const tick=async()=>{const j=await jget('/scan/'+id);render(j);
  if(j.status==='done'||j.status==='failed'){clearInterval(poll);refresh();}};tick();poll=setInterval(tick,1200);}
async function refresh(){try{const {jobs}=await jget('/jobs?limit=80');
  $('#list').innerHTML=jobs.length?jobs.map(j=>`<div class="job" onclick="watch('${j.job_id}')">
    <span class="fn" title="${esc(j.filename)}">${esc(j.filename)}</span>
    ${pill(j.verdict||j.status)}${j.graveyard_hit?' <span class="flag bad">graveyard</span>':''}</div>`).join('')
    :'<div class="empty">none yet</div>';}catch(e){}}
function flags(c){const f=[];const F=(ok,t,bad)=>f.push(`<span class="flag ${ok?'ok':(bad?'bad':'')}">${t}</span>`);
  if(c.chains_to_trusted_root!=null)F(c.chains_to_trusted_root,'trusted root',!c.chains_to_trusted_root);
  if(c.revoked)F(false,'revoked',true); if(c.explicit_distrust)F(false,'distrusted',true);
  if(c.valid_at_sign_time!=null)F(c.valid_at_sign_time,'valid@sign',!c.valid_at_sign_time);
  if(c.revocation_checked)f.push(`<span class="flag">rev: ${esc(c.revocation_checked)}</span>`); return f.join('');}
function certRow(c){const cn=c.subject_cn||c.subject||'—';
  return `<li><b>${esc(cn)}</b> ${c.self_signed?'<span class="flag bad">self-signed</span>':''}
    <div class="muted">issuer: ${esc(c.issuer_cn||c.issuer||'—')}${c.not_after?' · expires '+esc(c.not_after.slice(0,10)):''}</div>
    ${c.tbs_sha256?`<div class="mono"><a onclick="cert('${c.tbs_sha256}')">${esc(c.tbs_sha256)}</a></div>`:''}</li>`;}
function render(j){const rs=j.result_summary||{}, v=rs.verdict, w=rs.warnings||[];
  if(j.status==='queued'||j.status==='running'){
    $('#detail').innerHTML=`<h3>${esc(j.filename)}</h3>${pill(j.status)} <span class="muted">validating…</span>`;return;}
  if(!v){$('#detail').innerHTML=`<h3>${esc(j.filename)}</h3>${pill(j.status)}
    <div class="muted" style="margin-top:8px">${esc(j.error||'no verdict')}</div>`;return;}
  const s=v.signer||{}, ch=v.chain||{}, gv=v.graveyard||{};
  let h=`<h3>${esc(j.filename)}</h3><div style="margin:6px 0 14px">${pill(v.status)}
    <span class="flag">${esc(v.signature_type)}</span>${v.is_os_binary?'<span class="flag ok">OS binary</span>':''}
    ${v.content_verified===false?'<span class="flag bad">content unverified</span>':''}
    ${w.map(x=>`<span class="flag bad">${esc(x)}</span>`).join('')}</div>`;
  if(gv&&(gv.hit||gv.malware)) h+=`<div class="gv"><b>cert-graveyard hit</b> ${gv.matched_on?'· matched on '+esc(gv.matched_on):''}
    <div>${esc(gv.malware||gv.malware_type||'')} ${gv.malware_notes?'— '+esc(gv.malware_notes):''}</div></div>`;
  h+='<table>'; const row=(k,val)=>{if(val==null||val==='')return;h+=`<tr><td class="k">${k}</td><td>${val}</td></tr>`;};
  row('file sha256',`<span class="mono">${esc(v.file_sha256)}</span>`);
  if(s.subject||s.subject_cn) row('signer',`${esc(s.subject_cn||s.subject)}<div class="muted">issuer ${esc(s.issuer_cn||s.issuer||'—')}</div>
    <div class="muted">${esc((s.not_before||'').slice(0,10))} → ${esc((s.not_after||'').slice(0,10))}</div>`);
  if(s.tbs_sha256) row('signer cert',`<span class="mono"><a onclick="cert('${s.tbs_sha256}')">${esc(s.tbs_sha256)}</a></span>`);
  if(ch.chain&&ch.chain.length) row('chain ('+ch.chain.length+')',`<div>${flags(ch)}</div><ul class="chain">${ch.chain.map(certRow).join('')}</ul>`);
  else if(Object.keys(ch).length) row('chain',flags(ch));
  if(v.timestamped) row('timestamp',`${esc((v.sign_time||'').replace('T',' ').slice(0,19))} ${v.sign_time_verified?'<span class="flag ok">verified</span>':'<span class="flag">unverified</span>'}<div class="muted">${esc((v.timestamper||{}).subject_cn||'')}</div>`);
  row('error',v.error?`<span class="mono">${esc(v.error)}</span>`:'');
  h+='</table>'; $('#detail').innerHTML=h;}
async function cert(tbs){const r=await jget('/cert/'+tbs);
  $('#detail').innerHTML=`<h3>cert <span class="mono">${esc(tbs)}</span></h3>
    <p class="muted">files signed by / chaining to this cert (${r.seen_in.length}):</p>
    ${r.seen_in.length?r.seen_in.map(x=>`<div class="job" onclick="watch('${x.job_id}')"><span class="fn">${esc(x.filename)}</span>${pill(x.status)}</div>`).join(''):'<div class="empty">none in this session</div>'}`;}
refresh();setInterval(refresh,5000);
</script></body></html>"""

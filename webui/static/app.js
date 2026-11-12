"use strict";
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const api=(p)=>fetch("/api/"+p).then(r=>r.json());
const post=(p,b)=>fetch("/api/"+p,{method:"POST",headers:{"X-IRForge":"1","Content-Type":"application/json"},body:JSON.stringify(b||{})}).then(r=>r.json());
const SEVC={critical:"#ff3b5c",high:"#ff8a3d",medium:"#f5c542",low:"#38bdf8",informational:"#7f93b0"};
const S={page:"overview",session:null,sum:null,env:null,run:null,evOff:0,evQ:"",evT:""};
const fmtT=t=>t?t.replace("T"," ").replace(/\.\d+Z$/," UTC").replace("Z"," UTC"):"—";
const sevTag=s=>`<span class="sev ${esc(s)}">${esc(s||"n/a")}</span>`;
const score=(n,s)=>`<span class="score"><b>${n}</b><span class="m"><i style="width:${n}%;background:${SEVC[s]||'#7f93b0'}"></i></span></span>`;

async function init(){
  S.env=await api("env");
  $("#exeDot").className="dot "+(S.env.exe?"ok":"bad");
  $("#exeTxt").textContent=S.env.exe?S.env.version||"engine ready":"irforge.exe not found";
  $("#admDot").className="dot "+(S.env.admin?"ok":"warn");
  $("#admTxt").textContent=S.env.admin?"Elevated · ETW available":"Not elevated · ETW limited";
  $$("#nav a").forEach(a=>a.onclick=()=>{S.page=a.dataset.p;S.evOff=0;nav();render()});
  $("#sessSel").onchange=e=>{S.session=e.target.value;load()};
  $("#runBtn").onclick=openModal;$("#cancelRun").onclick=()=>$("#modal").classList.add("hidden");
  $("#dClose").onclick=()=>$("#drawer").classList.add("hidden");
  $("#goRun").onclick=startRun;
  $("#dur").oninput=e=>$("#durVal").textContent=e.target.value;
  $$("#modeSeg button").forEach(b=>b.onclick=()=>{$$("#modeSeg button").forEach(x=>x.classList.toggle("on",x===b));
    const r=b.dataset.m==="replay";$("#liveOpts").classList.toggle("hidden",r);$("#replayOpts").classList.toggle("hidden",!r);S.mode=b.dataset.m});
  $("#fixSel").innerHTML=S.env.fixtures.map(f=>`<option>${esc(f)}</option>`).join("");
  $("#admNote").textContent=S.env.admin?"Elevated: process lifecycle (ETW) will be collected.":"Not elevated: process ETW will be degraded (network + registry still collected). Restart this console as Administrator for full coverage.";
  S.mode="monitor";
  await refreshSessions(true);
  pollRun();setInterval(pollRun,1500);
}
function nav(){$$("#nav a").forEach(a=>a.classList.toggle("on",a.dataset.p===S.page))}
async function refreshSessions(pick){
  const l=await api("sessions");S.sessions=l;
  $("#sessSel").innerHTML=l.map(s=>`<option value="${esc(s.name)}">${esc(s.name)} · ${esc(s.mode)} · ${s.events} ev · ${s.incidents} inc</option>`).join("")||"<option>no sessions</option>";
  if(pick||!S.session){S.session=(l.find(s=>s.name.startsWith("web-"))||l[0]||{}).name||null}
  if(S.session)$("#sessSel").value=S.session;
  await load();
}
async function load(){
  if(!S.session){S.sum=null;return render()}
  S.sum=await api(`session/${encodeURIComponent(S.session)}/summary`);
  $("#navInc").textContent=S.sum.kpi?.incidents||"";
  render();
}
function openModal(){$("#modal").classList.remove("hidden")}
async function startRun(){
  const b=S.mode==="replay"?{mode:"replay",fixture:$("#fixSel").value,rules:$("#ruleSel").value}:{mode:"monitor",duration:+$("#dur").value,rules:$("#ruleSel").value};
  const r=await post("run/start",b);$("#modal").classList.add("hidden");
  if(r.error){alert(r.error)}else{S.page="overview";nav();pollRun()}
}
let lastState="idle";
async function pollRun(){
  const r=await api("run");S.run=r;const c=$("#runChip");
  if(r.state==="running"){
    c.classList.remove("hidden");const pct=r.duration?Math.min(100,(r.elapsed/r.duration)*100):60;
    c.innerHTML=`<span class="pulse"></span>${esc(r.mode)} running · ${Math.round(r.elapsed||0)}s${r.duration?" / "+r.duration+"s":""}<span class="bar"><i style="width:${pct}%"></i></span><button class="btn ghost" id="stopB">stop</button>`;
    $("#stopB").onclick=()=>post("run/stop");
    $("#runBtn").disabled=true;
  }else{
    $("#runBtn").disabled=false;
    if(lastState==="running"){
      c.innerHTML=`<span class="dot ok"></span>run ${r.state}`;setTimeout(()=>c.classList.add("hidden"),4000);
      S.session=r.session;await refreshSessions(false);
    }else if(r.state==="idle")c.classList.add("hidden");
  }
  lastState=r.state;
  if(r.state==="running"&&S.page==="overview"&&!S.sum)render();
}
function render(){
  const v=$("#view");
  if(S.run?.state==="running"&&(!S.sum||S.sum.name!==S.run.session)){
    return v.innerHTML=`<div class="card"><h2>Collecting</h2><p>IRForge is observing this host. Findings will load when the run completes.</p><div class="log">${esc((S.run.log||[]).join("\n"))}</div></div>`;
  }
  if(!S.sum||S.sum.error)return v.innerHTML=`<div class="empty card"><b>No session loaded</b>Click <b style="display:inline;color:var(--accent)">▶ New scan</b> to run IRForge on this PC.</div>`;
  ({overview,incidents,events,processes,network,health}[S.page])(v);
}
function head(t,sub){return `<h1>${t}</h1><div class="muted" style="margin-bottom:20px">${sub}</div>`}

/* ---------- Overview ---------- */
function overview(v){
  const s=S.sum,k=s.kpi,m=s.meta||{};
  const top=s.incidents[0];
  const bn=top?`<div class="banner hot"><span class="ic">⚠</span><div><b>${k.incidents} incident${k.incidents>1?"s":""} require triage</b><div class="muted">Highest: ${sevTag(top.severity)} score ${top.score} — ${esc(top.local_incident_id||top.incident_id)}. Scores are triage heuristics, not infection verdicts.</div></div></div>`
   :`<div class="banner clean"><span class="ic">✔</span><div><b>No rule matches in this session</b><div class="muted">Observation only — absence of findings is not proof the host is clean. Check sensor coverage.</div></div></div>`;
  const degraded=Object.entries(s.health?.sources||{}).filter(([_,x])=>x.state==="degraded"||x.state==="failed");
  const dg=degraded.length?`<div class="banner warn"><span class="ic">◐</span><div><b>Degraded coverage: ${degraded.map(d=>esc(d[0])).join(", ")}</b><div class="muted">${esc(degraded[0][1].message).slice(0,200)}</div></div></div>`:"";
  v.innerHTML=head("Overview",`${esc(m.host||"?")} · ${esc(m.mode||"")} · ${fmtT(m.start_utc)} → ${fmtT(m.stop_utc)} · <span class="tag ${m.result==='complete'?'ok':''}">${esc(m.result||"")}</span>`)+bn+dg+`
  <div class="grid g4" style="margin-bottom:16px">
   <div class="card kpi ${k.incidents?'alert':''}"><div class="l">Incidents</div><div class="v">${k.incidents}</div><div class="s">rule-correlated</div></div>
   <div class="card kpi"><div class="l">Events</div><div class="v">${k.events.toLocaleString()}</div><div class="s">${Object.keys(s.sources).length} sources</div></div>
   <div class="card kpi"><div class="l">Processes</div><div class="v">${k.processes}</div><div class="s">${k.exits} exits seen</div></div>
   <div class="card kpi"><div class="l">Connections</div><div class="v">${k.connections}</div><div class="s">${k.listening} listeners</div></div>
   <div class="card kpi"><div class="l">Public remotes</div><div class="v">${k.public_remotes}</div><div class="s">distinct IPs</div></div>
  </div>
  <div class="grid g2" style="margin-bottom:16px">
   <div class="card"><h2>Activity timeline</h2>${timelineSvg(s.timeline)}</div>
   <div class="card"><h2>Severity</h2>${donut(s.severity)}<h2 style="margin-top:22px">ATT&amp;CK techniques</h2>${techs(s.techniques)}</div>
  </div>
  <div class="grid g3">
   <div class="card"><h2>Event types</h2>${bars(Object.entries(s.types).sort((a,b)=>b[1]-a[1]))}</div>
   <div class="card"><h2>Top remote endpoints</h2>${bars(s.top_remote.map(r=>[r.ip+(r.public?"  ◉":""),r.count]))}</div>
   <div class="card"><h2>Network by process</h2>${bars(s.top_net_procs)}</div>
  </div>
  ${s.incidents.length?`<div class="card" style="margin-top:16px"><h2>Top incidents</h2>${incTable(s.incidents.slice(0,5))}</div>`:""}`;
  bindInc(v);
}
function bars(rows){if(!rows.length)return `<div class="muted">No data</div>`;const mx=Math.max(...rows.map(r=>r[1]));
  return `<div class="bars">${rows.map(r=>`<div class="r"><span title="${esc(r[0])}">${esc(r[0])}</span><div class="t"><i style="width:${r[1]/mx*100}%"></i></div><span class="mono muted">${r[1]}</span></div>`).join("")}</div>`}
function techs(t){return t.length?t.map(x=>`<a class="tag atk" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${esc(x.id).replace(".","/")}" title="${esc((x.tactics||[]).join(", "))}">${esc(x.id)}${x.name?" · "+esc(x.name):""}</a>`).join(""):`<span class="muted">None mapped</span>`}
function donut(sev){const order=["critical","high","medium","low","informational"];const tot=order.reduce((a,k)=>a+(sev[k]||0),0);
  if(!tot)return `<div class="muted">No incidents</div>`;let off=0;const R=42,C=2*Math.PI*R;
  const seg=order.filter(k=>sev[k]).map(k=>{const l=sev[k]/tot*C;const e=`<circle r="${R}" cx="55" cy="55" fill="none" stroke="${SEVC[k]}" stroke-width="14" stroke-dasharray="${l} ${C-l}" stroke-dashoffset="${-off}" transform="rotate(-90 55 55)"/>`;off+=l;return e}).join("");
  return `<div class="donut"><svg width="110" height="110">${seg}<text x="55" y="61" text-anchor="middle" fill="#dbe6f5" font-size="22" font-weight="700">${tot}</text></svg><ul>${order.filter(k=>sev[k]).map(k=>`<li><i style="background:${SEVC[k]}"></i>${k} <b>${sev[k]}</b></li>`).join("")}</ul></div>`}
function timelineSvg(t){
  if(!t||!t.series)return `<div class="muted">No timeline</div>`;
  const W=700,H=170,n=48,cols={process:"#00e5a8",network:"#38bdf8",registry:"#f5c542",other:"#7f93b0"};
  const keys=Object.keys(t.series);const tot=Array.from({length:n},(_,i)=>keys.reduce((a,k)=>a+t.series[k][i],0));const mx=Math.max(1,...tot);const bw=W/n;
  let rects="";for(let i=0;i<n;i++){let y=H-18;for(const k of keys){const h=t.series[k][i]/mx*(H-30);if(h>0){y-=h;rects+=`<rect x="${i*bw+1}" y="${y}" width="${bw-2}" height="${h}" rx="2" fill="${cols[k]}" opacity=".9"/>`}}}
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${[0,.5,1].map(f=>`<line x1="0" x2="${W}" y1="${H-18-f*(H-30)}" y2="${H-18-f*(H-30)}" stroke="#1c2a40" stroke-dasharray="3 4"/>`).join("")}${rects}</svg>
  <div class="legend">${keys.map(k=>`<span><i style="background:${cols[k]}"></i>${k}</span>`).join("")}<span class="grow"></span><span class="mono">${fmtT(t.t0)} → ${fmtT(t.t1)}</span></div>`}

/* ---------- Incidents ---------- */
function incTable(rows){return `<table><thead><tr><th>Severity</th><th>Score</th><th>Incident</th><th>Techniques</th><th>Rules</th><th>First seen</th></tr></thead><tbody>${rows.map(i=>`<tr class="click" data-i="${esc(i.incident_id)}"><td>${sevTag(i.severity)}</td><td>${score(i.score,i.severity)}</td><td><b>${esc(i.local_incident_id||i.incident_id)}</b><div class="muted tiny">${esc(i.title||"")} · confidence ${esc(i.confidence)}</div></td><td>${(i.attack_techniques||[]).map(t=>`<span class="tag atk">${esc(t.id)}</span>`).join("")}</td><td class="mono">${(i.rule_ids||[]).map(r=>`<span class="tag">${esc(r)}</span>`).join("")}</td><td class="mono tiny">${fmtT(i.first_seen_utc)}</td></tr>`).join("")}</tbody></table>`}
function bindInc(r){$$("tr[data-i]",r).forEach(t=>t.onclick=()=>openIncident(t.dataset.i))}
function incidents(v){
  v.innerHTML=head("Incidents","Correlated rule matches with explainable scoring")+(S.sum.incidents.length?`<div class="card">${incTable(S.sum.incidents)}</div>`:`<div class="card empty"><b>No incidents</b>No detection rule matched the observed activity.</div>`);bindInc(v)}
async function openIncident(id){
  const d=await api(`session/${encodeURIComponent(S.session)}/incident/${encodeURIComponent(id)}`);if(d.error)return;
  const i=d.incident,ev=d.events;
  $("#dTitle").innerHTML=`${sevTag(i.severity)} &nbsp;${esc(i.local_incident_id||i.incident_id)}`;
  const rules=(i.matched_rules||[]).map(m=>`<div class="card" style="padding:12px;margin-bottom:10px"><div style="display:flex;justify-content:space-between"><b class="mono">${esc(m.rule_id)}</b><span class="tag">+${m.points} pts</span></div><div style="margin:6px 0">${esc(m.reason)}</div>${(m.attack||[]).map(a=>`<span class="tag atk">${esc(a)}</span>`).join("")}<span class="tag">confidence ${esc(m.confidence||"")}</span><span class="tag">events ${esc((m.event_ids||[]).join(", "))}</span></div>`).join("");
  const tl=ev.map(e=>`<div class="it ${e.event_type.startsWith('process')?'proc':e.event_type.startsWith('tcp')?'net':''}"><div class="when">${fmtT(e.timestamp_utc)} · #${e.event_id} · ${esc(e.event_type)}</div><div class="mono" style="word-break:break-all">${esc(evLabel(e))}</div></div>`).join("");
  const lim=(i.limitations||[]).map(l=>`<li>${esc(l)}</li>`).join("");
  $("#dBody").innerHTML=`<div style="display:flex;gap:18px;align-items:center;margin-bottom:14px"><div style="font-size:44px;font-weight:800;color:${SEVC[i.severity]}">${i.score}</div><div class="muted">risk score (capped sum of distinct rules)<br>confidence <b style="color:var(--text)">${esc(i.confidence)}</b> · status <b style="color:var(--text)">${esc(i.status)}</b></div></div>
  <p>${esc(i.explanation||i.summary||"")}</p>
  <h2 style="margin-top:20px">ATT&amp;CK</h2>${techs(i.attack_techniques||[])}
  <h2 style="margin-top:20px">Matched rules</h2>${rules}
  <h2 style="margin-top:20px">Evidence timeline</h2><div class="tl">${tl||'<span class="muted">No events</span>'}</div>
  ${lim?`<h2 style="margin-top:20px">Limitations</h2><ul class="muted tiny">${lim}</ul>`:""}`;
  $("#drawer").classList.remove("hidden");
}
function evLabel(e){const p=e.payload||{};
  if(e.event_type.startsWith("process"))return (p.command_line||p.image_path||"")+(p.parent_pid!=null?`   [pid ${p.identity?.pid} ← ppid ${p.parent_pid}]`:"");
  if(e.event_type.startsWith("tcp"))return `${p.local_address}:${p.local_port} → ${p.remote_address}:${p.remote_port}  ${p.state}  (pid ${p.owner_pid})`;
  return JSON.stringify(p)}

/* ---------- Events ---------- */
async function events(v){
  if(!v.querySelector("#evQ")){
    v.innerHTML=head("Events","Normalized observations from all collectors")+`<div class="toolbar"><input type="search" id="evQ" placeholder="Search command line, process, IP, pid…" value="${esc(S.evQ)}"><select id="evT"><option value="">All types</option>${Object.keys(S.sum.types).filter(t=>t!=="monitor_status").map(t=>`<option ${S.evT===t?"selected":""}>${esc(t)}</option>`).join("")}</select><span class="muted" id="evCnt"></span></div><div class="scroll"><table><thead><tr><th>Time</th><th>Type</th><th>Process</th><th>PID</th><th>Detail</th></tr></thead><tbody id="evB"></tbody></table></div><button class="btn more hidden" id="evMore">Load more</button>`;
    let tm;$("#evQ").oninput=e=>{clearTimeout(tm);tm=setTimeout(()=>{S.evQ=e.target.value;S.evOff=0;fetchEv(true)},250)};
    $("#evT").onchange=e=>{S.evT=e.target.value;S.evOff=0;fetchEv(true)};$("#evMore").onclick=()=>fetchEv(false);
  }
  fetchEv(true);
}
async function fetchEv(reset){
  const lim=150;if(reset)S.evOff=0;
  const r=await api(`session/${encodeURIComponent(S.session)}/events?q=${encodeURIComponent(S.evQ)}&type=${encodeURIComponent(S.evT)}&offset=${S.evOff}&limit=${lim}`);
  const html=r.rows.map(e=>`<tr class="click" data-raw="${esc(JSON.stringify(e.raw,null,2))}"><td class="mono tiny" style="white-space:nowrap">${fmtT(e.ts).replace(" UTC","")}</td><td><span class="tag">${esc(e.type)}</span></td><td>${esc(e.proc)}</td><td class="mono">${e.pid??""}</td><td class="cmd">${esc((e.label||"").slice(0,400))}</td></tr>`).join("");
  const b=$("#evB");if(!b)return;if(reset)b.innerHTML="";b.insertAdjacentHTML("beforeend",html);S.evOff+=r.rows.length;
  $("#evCnt").textContent=`${r.total.toLocaleString()} matching`;$("#evMore").classList.toggle("hidden",S.evOff>=r.total);
  $$("tr[data-raw]",b).forEach(t=>t.onclick=()=>{$("#dTitle").textContent="Raw event";$("#dBody").innerHTML=`<div class="raw">${t.dataset.raw}</div>`;$("#drawer").classList.remove("hidden")});
}

/* ---------- Processes ---------- */
async function processes(v){
  v.innerHTML=head("Processes","Process generations seen via ETW (flagged = linked to an incident)")+`<div class="toolbar"><input type="search" id="pq" placeholder="Filter name, pid, command line…"><span class="muted" id="pc"></span></div><div class="scroll"><table><thead><tr><th>PID</th><th>PPID</th><th>Name</th><th>Conns</th><th>Started</th><th>Command line</th></tr></thead><tbody id="pb"></tbody></table></div>`;
  const rows=await api(`session/${encodeURIComponent(S.session)}/processes`);
  const draw=()=>{const q=$("#pq").value.toLowerCase();const f=rows.filter(r=>!q||(r.name+r.pid+(r.cmd||"")+(r.path||"")).toLowerCase().includes(q)).slice(0,600);
    $("#pc").textContent=`${f.length} of ${rows.length}`;
    $("#pb").innerHTML=f.map(r=>`<tr><td class="mono">${r.pid}</td><td class="mono muted">${r.ppid??""}</td><td><b>${esc(r.name)}</b> ${r.flagged?'<span class="tag flag">incident</span>':""}${r.initial?'<span class="tag">pre-existing</span>':""}${r.exited?'<span class="tag">exited</span>':""}</td><td class="mono">${r.conns||""}</td><td class="mono tiny">${fmtT(r.start).replace(" UTC","")}</td><td class="cmd">${esc((r.cmd||r.path||"").slice(0,300))}</td></tr>`).join("")};
  $("#pq").oninput=draw;draw();
}

/* ---------- Network ---------- */
async function network(v){
  v.innerHTML=head("Network","TCP endpoints observed by snapshot polling (direction unknown, short connections may be missed)")+`<div class="toolbar"><input type="search" id="nq" placeholder="Filter IP, port, process…"><label class="muted"><input type="checkbox" id="nl"> include listeners</label><label class="muted"><input type="checkbox" id="np"> public only</label><span class="muted" id="nc"></span></div><div class="scroll"><table><thead><tr><th>Process</th><th>PID</th><th>Local</th><th>Remote</th><th>State</th><th>Last seen</th></tr></thead><tbody id="nb"></tbody></table></div>`;
  const rows=await api(`session/${encodeURIComponent(S.session)}/network`);
  const draw=()=>{const q=$("#nq").value.toLowerCase(),l=$("#nl").checked,p=$("#np").checked;
    const f=rows.filter(r=>(l||r.state!=="LISTEN")&&(!p||r.public)&&(!q||(r.proc+r.local+r.remote+r.pid).toLowerCase().includes(q))).slice(0,800);
    $("#nc").textContent=`${f.length} shown`;
    $("#nb").innerHTML=f.map(r=>`<tr><td><b>${esc(r.proc||"—")}</b></td><td class="mono">${r.pid}</td><td class="mono">${esc(r.local)}</td><td class="mono">${esc(r.remote)} ${r.public?'<span class="tag pub">public</span>':""}</td><td><span class="tag ${r.state==='ESTABLISHED'?'ok':''}">${esc(r.state)}</span>${r.closed?'<span class="tag">closed</span>':""}</td><td class="mono tiny">${fmtT(r.last).replace(" UTC","")}</td></tr>`).join("")};
  ["nq","nl","np"].forEach(i=>$("#"+i).oninput=draw);draw();
}

/* ---------- Health ---------- */
function health(v){
  const h=S.sum.health||{},srcs=Object.entries(h.sources||{}),recv=h.events_received_by_source||{};
  const cards=srcs.length?srcs.map(([n,x])=>`<div class="card"><div style="display:flex;justify-content:space-between"><b>${esc(n)}</b><span class="tag ${x.state==='active'?'ok':x.state==='disabled'?'':'flag'}">${esc(x.state)}</span></div><div class="muted tiny" style="margin:8px 0">${esc((x.message||"").trim())}</div><div class="mono tiny">received ${recv[n]??0} · lost ${x.events_lost} · decode errors ${x.decode_errors}</div></div>`).join(""):`<div class="muted">No per-source health recorded for this session (replay/legacy).</div>`;
  v.innerHTML=head("Sensors & Health","What was actually collected — read this before trusting a clean result")+`<div class="grid g4" style="margin-bottom:16px">
   <div class="card kpi"><div class="l">Coverage</div><div class="v" style="font-size:22px">${esc(h.coverage||"n/a")}</div></div>
   <div class="card kpi"><div class="l">Queue drops</div><div class="v">${h.queue_drops??0}</div></div>
   <div class="card kpi"><div class="l">Events / sec</div><div class="v">${h.events_per_second_since_start?h.events_per_second_since_start.toFixed(1):"—"}</div></div>
   <div class="card kpi"><div class="l">Uptime</div><div class="v">${h.uptime_ms?(h.uptime_ms/1000).toFixed(0)+"s":"—"}</div></div></div>
   <div class="grid g3">${cards}</div>
   <div class="card" style="margin-top:16px"><h2>Engine log (last run)</h2><div class="log">${esc((S.run?.log||[]).join("\n")||"No run launched from this console in this server session.")}</div></div>`;
}
init();

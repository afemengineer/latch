"""Self-contained browser UI for the M9 hackathon demo."""

DEMO_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Latch — Authority Control for AI Agents</title>
<style>
:root {
  color-scheme: dark;
  --bg:#090b10; --panel:#11151d; --panel2:#171c26; --line:#283141;
  --text:#edf2f7; --muted:#8f9bad; --accent:#8ee6c2; --blue:#8ab4ff;
  --warn:#ffc76b; --danger:#ff7f88; --ok:#8ee6c2;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at 18% 0,#152128 0,#090b10 36%);
  color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}
header{padding:28px 34px 18px;border-bottom:1px solid var(--line);display:flex;
  align-items:end;justify-content:space-between;gap:20px}
h1{margin:0;font-size:30px;letter-spacing:-1px} h1 span{color:var(--accent)}
.tagline{color:var(--muted);max-width:720px;margin-top:6px}
.badge{display:inline-block;padding:4px 9px;border-radius:999px;background:#1b2530;
  border:1px solid #344357;color:var(--blue);font-size:12px}
main{padding:24px 34px 40px;display:grid;grid-template-columns:minmax(420px,1.3fr) minmax(330px,.7fr);
  gap:18px;max-width:1500px;margin:auto}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
  border-radius:14px;padding:18px;box-shadow:0 14px 34px #0005}
.card h2{font-size:15px;margin:0 0 13px;letter-spacing:.2px}
.full{grid-column:1/-1}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.stack{display:grid;gap:11px} label{color:var(--muted);font-size:12px}
textarea,input,select{width:100%;background:#0c1118;border:1px solid #303b4d;color:var(--text);
  border-radius:9px;padding:10px 11px;font:inherit;outline:none}
textarea{min-height:88px;resize:vertical} input:focus,textarea:focus,select:focus{border-color:#5e8e9b}
button{border:1px solid #405064;background:#1b2531;color:var(--text);padding:9px 13px;
  border-radius:9px;font-weight:650;cursor:pointer}
button:hover{background:#263244}button.primary{background:#163d34;border-color:#2b755f;color:#cffff0}
button.danger{background:#3d1d24;border-color:#72323e;color:#ffd7da}
button:disabled{opacity:.45;cursor:not-allowed}
.metric{padding:10px 12px;background:#0b1017;border:1px solid var(--line);border-radius:10px}
.metric b{display:block;font-size:12px;color:var(--muted);margin-bottom:3px}
.code{white-space:pre-wrap;overflow-wrap:anywhere;background:#080c12;border:1px solid #252e3c;
  border-radius:9px;padding:11px;color:#c6d0dd;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
.attack{border-color:#633642;background:#1b1015;color:#ffc6cc}
.ok{color:var(--ok)}.dangerText{color:var(--danger)}.warn{color:var(--warn)}
.permission{padding:12px;border:1px solid var(--line);border-radius:10px;background:#0d1219}
.permission .scope{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#b7c5d7;
  overflow-wrap:anywhere}
.timeline{display:grid;gap:8px;max-height:650px;overflow:auto;padding-right:5px}
.event{border-left:3px solid #536277;background:#0c1118;padding:10px 12px;border-radius:7px}
.event.deny{border-left-color:var(--danger)}.event.allow{border-left-color:var(--ok)}
.event.exec{border-left-color:var(--blue)}.event.approval{border-left-color:var(--warn)}
.event .meta{font-size:11px;color:var(--muted);margin-bottom:3px}
.event .summary{font-weight:650}.event pre{margin:6px 0 0;white-space:pre-wrap;color:#96a5b8;font-size:11px}
#approval{display:none;border:1px solid #806631;background:#211b10}
#approval.visible{display:block}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}
hr{border:0;border-top:1px solid var(--line);margin:14px 0}
.small{font-size:12px;color:var(--muted)}.result{font-size:16px;line-height:1.55}
.obs{padding:10px;border:1px solid var(--line);border-radius:8px;margin-top:8px}
.obs b{font-size:11px;color:var(--muted)}
details summary{cursor:pointer;color:#cdd6e3}
@media(max-width:900px){main{grid-template-columns:1fr;padding:16px}.full{grid-column:auto}header{padding:22px 16px}}
</style>
</head>
<body>
<header>
  <div>
    <h1><span>Latch</span> / containment demo</h1>
    <div class="tagline">Assume the model can be prompt-injected. Authority, information flow,
      execution and evidence stay deterministic.</div>
  </div>
  <div id="modeBadge" class="badge">loading…</div>
</header>
<main>
  <section class="card">
    <h2>1. Run the task</h2>
    <div class="stack">
      <div>
        <label for="taskRequest">User request</label>
        <textarea id="taskRequest"></textarea>
      </div>
      <div class="two">
        <div><label for="label">Input classification</label>
          <select id="label">
            <option value="public" selected>PUBLIC</option>
            <option value="private">PRIVATE</option>
            <option value="local_only">LOCAL_ONLY</option>
          </select>
        </div>
        <div><label>Task state</label><div id="taskState" class="metric">not started</div></div>
      </div>
      <div class="row">
        <button id="fullDemo" class="primary">Run deterministic containment demo</button>
        <button id="startTask">Start task</button>
        <button id="runTask">Run until pause</button>
        <button id="stepTask">Single step</button>
        <button id="resetDemo">Reset</button>
      </div>
      <div id="resultBox" class="metric" style="display:none">
        <b>Final result</b><div id="finalResult" class="result"></div>
      </div>
      <details>
        <summary>Model-visible observations</summary>
        <div id="observations"></div>
      </details>
    </div>
  </section>

  <aside class="card">
    <h2>2. Attack fixture</h2>
    <div class="stack">
      <div class="metric"><b>Provider</b><span id="provider"></span></div>
      <div class="metric"><b>Search executor</b><span id="searchService"></span></div>
      <div class="metric"><b>Allowed filesystem root</b><span id="allowedRoot"></span></div>
      <div class="metric"><b>Injected target outside ceiling</b><span id="attackTarget"></span></div>
      <div><label>Poisoned search result</label><div id="attackText" class="code attack"></div></div>
      <div class="small">The poisoned result is an explicit red-team fixture. The security claim is
        containment after model failure, not that every model naturally obeys this text.</div>
    </div>
  </aside>

  <section id="approval" class="card full">
    <h2>Permission request</h2>
    <div id="approvalTitle" style="font-size:18px;font-weight:700"></div>
    <div id="approvalDetail" class="small" style="margin:7px 0 12px"></div>
    <div class="row">
      <button id="allowOnce" class="primary">Allow once</button>
      <button id="alwaysAllow">Always allow this scope</button>
      <button id="denyApproval" class="danger">Block</button>
    </div>
  </section>

  <section class="card">
    <h2>3. Authority envelope</h2>
    <div id="permissionMeta" class="small"></div>
    <h3 style="font-size:12px;color:var(--muted)">MAXIMUM SKILL AUTHORITY</h3>
    <div id="ceiling" class="stack"></div>
    <h3 style="font-size:12px;color:var(--muted);margin-top:16px">STANDING PERMISSIONS</h3>
    <div id="standing" class="stack"></div>
    <h3 style="font-size:12px;color:var(--muted);margin-top:16px">APPROVED PRIVATE SINKS</h3>
    <div id="sinks" class="stack"></div>
  </section>

  <section class="card">
    <h2>4. Live Nebius + Tavily</h2>
    <div class="small" style="margin-bottom:10px">Credentials are sent only to the local control
      plane and placed into the sealed credential vault. They are never added to model context.</div>
    <div class="stack">
      <div><label>Nebius OpenAI-compatible base URL</label>
        <input id="nebiusUrl" placeholder="https://…/v1" autocomplete="off"></div>
      <div><label>Nebius model</label>
        <input id="nebiusModel" placeholder="NVIDIA/Nemotron model ID" autocomplete="off"></div>
      <div><label>Nebius API key</label>
        <input id="nebiusKey" type="password" autocomplete="off"></div>
      <div><label>Tavily API key</label>
        <input id="tavilyKey" type="password" autocomplete="off"></div>
      <label class="row" style="color:var(--text)">
        <input id="forceAttack" type="checkbox" checked style="width:auto">
        Force the live model down the adversarial branch for a deterministic containment test
      </label>
      <div class="row"><button id="configureLive" class="primary">Configure live mode</button>
        <button id="useScripted">Use scripted mode</button></div>
      <div id="liveStatus" class="small"></div>
    </div>
  </section>

  <section class="card full">
    <div class="row" style="justify-content:space-between">
      <h2 style="margin:0">5. Proof-carrying timeline</h2>
      <div id="chain" class="badge">chain: …</div>
    </div>
    <div class="small" style="margin:8px 0 12px">Raw model reasoning is not shown. This is the
      deterministic record of proposals, policy decisions, grants, execution and outcomes.</div>
    <div id="timeline" class="timeline"></div>
  </section>
</main>
<script>
let state = null;

function el(id){ return document.getElementById(id); }
function setText(id, value){ el(id).textContent = value == null ? "" : String(value); }

async function api(path, body){
  const options = {method: body === undefined ? "GET" : "POST", headers:{}};
  if(body !== undefined){
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if(!response.ok) throw new Error(data.detail || "Request failed");
  state = data;
  render();
  return data;
}

function eventClass(event){
  const s = (event.summary + " " + JSON.stringify(event.details)).toLowerCase();
  if(s.includes("denied") || s.includes('"outcome":"deny"')) return "deny";
  if(event.kind === "approval") return "approval";
  if(event.kind.includes("execution") || event.kind.includes("verification")) return "exec";
  if(event.kind === "task_completed") return "allow";
  return "";
}

function render(){
  if(!state) return;
  setText("modeBadge", state.mode.toUpperCase() + (state.scenario.force_adversarial_model ? " / RED TEAM" : ""));
  if(!el("taskRequest").value) el("taskRequest").value = state.default_request;

  const task = state.task;
  setText("taskState", task ? task.state + " · turn " + task.turn_count : "not started");
  el("resultBox").style.display = task && task.final_text ? "block" : "none";
  setText("finalResult", task ? task.final_text : "");

  const obs = el("observations"); obs.replaceChildren();
  if(task){
    task.observations.forEach(item => {
      const div = document.createElement("div"); div.className = "obs";
      const meta = document.createElement("b");
      meta.textContent = item.label.toUpperCase() + " · " + item.origin;
      const text = document.createElement("div"); text.className = "code"; text.textContent = item.text;
      div.append(meta,text); obs.append(div);
    });
  }

  setText("provider", state.scenario.provider);
  setText("searchService", state.scenario.search_service);
  setText("allowedRoot", state.scenario.allowed_root);
  setText("attackTarget", state.scenario.attack_target);
  setText("attackText", state.scenario.attack_text);

  const p = state.permissions;
  setText("permissionMeta", p.display_name + " · revision " + p.revision);
  renderPermissions("ceiling", p.authority_ceiling, false);
  renderPermissions("standing", p.standing_capabilities, true);
  const sinks = el("sinks"); sinks.replaceChildren();
  if(!p.approved_private_sinks.length) addEmpty(sinks, "None");
  p.approved_private_sinks.forEach(item => {
    const div = document.createElement("div"); div.className="permission";
    const title = document.createElement("strong"); title.textContent = item.kind + " → " + item.target;
    const detail = document.createElement("div"); detail.className="small"; detail.textContent=item.consequence.detail;
    div.append(title,detail); sinks.append(div);
  });

  const pending = task ? task.pending : null;
  el("approval").classList.toggle("visible", !!pending);
  if(pending){
    setText("approvalTitle", pending.title + " · " + String(pending.risk).toUpperCase());
    setText("approvalDetail", pending.detail);
    el("alwaysAllow").style.display = pending.can_persist ? "inline-block" : "none";
  }

  const timeline = el("timeline"); timeline.replaceChildren();
  state.evidence.forEach(event => {
    const div=document.createElement("div"); div.className="event " + eventClass(event);
    const meta=document.createElement("div"); meta.className="meta";
    meta.textContent = "#" + event.sequence + " · " + event.kind + " · " + event.task_id;
    const summary=document.createElement("div"); summary.className="summary"; summary.textContent=event.summary;
    const details=document.createElement("pre"); details.textContent=JSON.stringify(event.details,null,2);
    div.append(meta,summary,details); timeline.append(div);
  });
  el("chain").textContent = state.evidence_chain.valid
    ? "SHA-256 chain valid · " + state.evidence_chain.checked_events + " events"
    : "CHAIN INVALID";

  setText("liveStatus", state.live_configured
    ? "Live credentials configured. Current mode: " + state.mode
    : "Live mode not configured.");
}

function renderPermissions(id, items, standing){
  const root=el(id); root.replaceChildren();
  if(!items.length){ addEmpty(root,"None"); return; }
  items.forEach(item => {
    const div=document.createElement("div"); div.className="permission";
    const title=document.createElement("strong");
    title.textContent=(item.operations || []).join(", ");
    const scope=document.createElement("div"); scope.className="scope"; scope.textContent=item.scope;
    div.append(title,scope);
    if(standing && item.consequence){
      const d=document.createElement("div"); d.className="small"; d.textContent=item.consequence.detail; div.append(d);
    }
    root.append(div);
  });
}
function addEmpty(root,text){ const d=document.createElement("div"); d.className="small"; d.textContent=text; root.append(d); }
function showError(error){ alert(error instanceof Error ? error.message : String(error)); }

el("fullDemo").onclick = async () => {
  try{
    await api("/api/demo/reset",{mode:"scripted"});
    el("taskRequest").value=state.default_request; el("label").value="public";
    await api("/api/task",{request:el("taskRequest").value,label:"public"});
    await api("/api/task/run",{max_steps:8});
  }catch(e){showError(e);}
};
el("startTask").onclick=async()=>{try{await api("/api/task",{request:el("taskRequest").value,label:el("label").value});}catch(e){showError(e);}};
el("runTask").onclick=async()=>{try{await api("/api/task/run",{max_steps:8});}catch(e){showError(e);}};
el("stepTask").onclick=async()=>{try{await api("/api/task/step",{});}catch(e){showError(e);}};
el("resetDemo").onclick=async()=>{try{await api("/api/demo/reset",{mode:state.mode});}catch(e){showError(e);}};
el("allowOnce").onclick=async()=>{try{await api("/api/task/approve",{approved_by:"local-user",persist:false});}catch(e){showError(e);}};
el("alwaysAllow").onclick=async()=>{try{await api("/api/task/approve",{approved_by:"local-user",persist:true});}catch(e){showError(e);}};
el("denyApproval").onclick=async()=>{try{await api("/api/task/deny",{denied_by:"local-user"});}catch(e){showError(e);}};
el("useScripted").onclick=async()=>{try{await api("/api/demo/reset",{mode:"scripted"});}catch(e){showError(e);}};
el("configureLive").onclick=async()=>{
  try{
    await api("/api/live/configure",{
      nebius_api_key:el("nebiusKey").value,
      tavily_api_key:el("tavilyKey").value,
      nebius_base_url:el("nebiusUrl").value,
      nebius_model:el("nebiusModel").value,
      force_adversarial_model:el("forceAttack").checked
    });
    el("nebiusKey").value=""; el("tavilyKey").value="";
  }catch(e){showError(e);}
};

api("/api/state").catch(showError);
</script>
</body>
</html>
"""

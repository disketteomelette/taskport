#!/usr/bin/python3
from flask import Flask, jsonify, render_template_string, request, send_file, abort
import psutil, time, os, signal, ipaddress, datetime, tempfile, json, threading, collections

app = Flask(__name__)

SELF_PORT=1010
RULES_PATH="./rules.json"
STANDARD_EXE_PREFIXES=("/usr/bin/","/bin/","/usr/sbin/","/sbin/","/usr/local/bin/")

last={}
first_seen={}
RULES=[]
RULE_DEFS={}
LOG_EVENTS=collections.deque(maxlen=4000)
LOG_ALERT_EVENTS=collections.deque(maxlen=2000)
EVENT_SEQ=0

def load_rules():
    global RULES,RULE_DEFS
    with open(RULES_PATH,"r",encoding="utf-8") as f: obj=json.load(f)
    rules=obj.get("rules",[]); rules=rules if isinstance(rules,list) else []
    RULES=[r for r in rules if r.get("enabled",True) and r.get("id")]
    RULE_DEFS={r["id"]:{ "badge":r.get("badge",r["id"]), "severity":int(r.get("severity",1)), "description":r.get("description",{"why":"","fp":"","what":""}) } for r in RULES}

def _is_number(x): return isinstance(x,(int,float)) and not isinstance(x,bool)
def _cmp(op,a,b):
    if op=="eq": return a==b
    if op=="neq": return a!=b
    if op=="gt": return _is_number(a) and _is_number(b) and a>b
    if op=="gte": return _is_number(a) and _is_number(b) and a>=b
    if op=="lt": return _is_number(a) and _is_number(b) and a<b
    if op=="lte": return _is_number(a) and _is_number(b) and a<=b
    return False

def eval_leaf(cond,ctx):
    field=cond.get("field"); op=cond.get("op"); val=cond.get("value"); v=ctx.get(field)
    try:
        if op in {"eq","neq","gt","gte","lt","lte"}: return _cmp(op,v,val)
        if op=="in": return isinstance(val,list) and v in val
        if op=="not_in": return isinstance(val,list) and v not in val
        if op=="starts_with": return isinstance(v,str) and isinstance(val,str) and v.startswith(val)
        if op=="ends_with": return isinstance(v,str) and isinstance(val,str) and v.endswith(val)
        if op=="contains":
            if isinstance(v,str) and isinstance(val,str): return val in v
            if isinstance(v,list): return val in v
            return False
        if op=="contains_any":
            if isinstance(v,str) and isinstance(val,list): return any(isinstance(x,str) and x in v for x in val)
            if isinstance(v,list) and isinstance(val,list): return any(x in v for x in val)
            return False
    except Exception: return False
    return False

def eval_expr(expr,ctx):
    if not isinstance(expr,dict): return False
    if "all" in expr:
        items=expr.get("all",[])
        return isinstance(items,list) and all(eval_expr(x,ctx) for x in items)
    if "any" in expr:
        items=expr.get("any",[])
        return isinstance(items,list) and any(eval_expr(x,ctx) for x in items)
    if "not" in expr: return not eval_expr(expr.get("not"),ctx)
    if "field" in expr and "op" in expr: return eval_leaf(expr,ctx)
    return False

def apply_rules_fixpoint(base_ctx):
    alerts=[]; ctx=dict(base_ctx); ctx["alerts"]=alerts
    enabled=[r for r in RULES if r.get("enabled",True) and r.get("id")]
    max_iter=max(1,len(enabled))
    for _ in range(max_iter):
        changed=False
        for r in enabled:
            rid=r.get("id"); when=r.get("when",{})
            if rid in alerts: continue
            if eval_expr(when,ctx): alerts.append(rid); changed=True
        if not changed: break
    return alerts

load_rules()

NET_INTERVAL_S=2.0
NET_MAX_POINTS=300
NET_TMP_PATH=os.path.join(tempfile.gettempdir(),f"traykill_net_{os.getpid()}.jsonl")

net_hist=collections.deque(maxlen=NET_MAX_POINTS)
net_marks=collections.deque(maxlen=NET_MAX_POINTS)
net_lock=threading.Lock()
_last_net=None

def now_ts(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def _append_tmp(obj):
    try:
        with open(NET_TMP_PATH,"a",encoding="utf-8") as f: f.write(json.dumps(obj,ensure_ascii=False)+"\n")
    except Exception: pass

def human_rate(bps):
    units=["B/s","KB/s","MB/s","GB/s"]; v=float(max(0.0,bps))
    for u in units:
        if v<1024 or u==units[-1]: return f"{v:.1f} {u}"
        v/=1024
    return f"{v:.1f} B/s"

def _net_loop():
    global _last_net
    while True:
        try:
            io=psutil.net_io_counters(); t=time.time()
            if _last_net is None:
                _last_net=(io.bytes_sent,io.bytes_recv,t)
                point={"t":now_ts(),"tx_bps":0.0,"rx_bps":0.0,"tx":"0.0 B/s","rx":"0.0 B/s"}
            else:
                bs0,br0,t0=_last_net; dt=max(0.001,t-t0)
                tx_bps=(io.bytes_sent-bs0)/dt; rx_bps=(io.bytes_recv-br0)/dt
                _last_net=(io.bytes_sent,io.bytes_recv,t)
                point={"t":now_ts(),"tx_bps":tx_bps,"rx_bps":rx_bps,"tx":human_rate(tx_bps),"rx":human_rate(rx_bps)}
            with net_lock:
                net_hist.append(point)
                idx=len(net_hist)-1
            _append_tmp({"type":"net","i":idx,**point})
        except Exception: pass
        time.sleep(NET_INTERVAL_S)

threading.Thread(target=_net_loop,daemon=True).start()

def is_public_ip(ip_str):
    try:
        ip=ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except Exception: return False

def fmt_age(seconds):
    seconds=max(0,seconds); m,s=divmod(int(seconds),60); h,m=divmod(m,60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def short_path(p,maxlen=48): return "" if not p else (p if len(p)<=maxlen else ("…"+p[-(maxlen-1):]))

def kill_process(pid):
    try:
        p=psutil.Process(pid); p.terminate(); p.wait(timeout=2)
    except Exception:
        try: os.kill(pid,signal.SIGKILL)
        except Exception: pass

def proc_info(pid):
    p=psutil.Process(pid)
    info={"pid":pid,"name":p.name(),"exe":p.exe(),"cmdline":" ".join(p.cmdline()),"user":p.username(),"status":p.status(),"ppid":p.ppid(),"create_time":p.create_time()}
    try: parent=p.parent(); info["parent_name"]=parent.name() if parent else ""
    except Exception: info["parent_name"]=""
    try: info["cpu_percent"]=p.cpu_percent(interval=None)
    except Exception: info["cpu_percent"]=None
    try: info["rss_mb"]=round(p.memory_info().rss/(1024*1024),1)
    except Exception: info["rss_mb"]=None
    return info

def snapshot():
    now=time.time(); data={}; per_pid_total={}
    for c in psutil.net_connections(kind="inet"):
        if not c.laddr or not c.pid: continue
        per_pid_total[c.pid]=per_pid_total.get(c.pid,0)+1
    proc_cache={}
    for pid in per_pid_total.keys():
        try:
            p=psutil.Process(pid)
            name=p.name(); user=p.username(); exe=p.exe()
            try:
                parent=p.parent()
                parent_txt=f"{parent.pid}:{parent.name()}" if parent else ""
            except Exception:
                parent_txt=""
            try:
                rss_mb=round(p.memory_info().rss/(1024*1024),1)
            except Exception:
                rss_mb=None
            proc_cache[pid]={"name":name,"user":user,"exe":exe,"rss_mb":rss_mb,"parent":parent_txt}
        except Exception:
            proc_cache[pid]={"name":"","user":"","exe":"","rss_mb":None,"parent":""}

    for c in psutil.net_connections(kind="inet"):
        if not c.laddr or not c.pid: continue
        r_ip=c.raddr.ip if c.raddr else ""; r_port=c.raddr.port if c.raddr else 0
        is_self=(c.laddr.port==SELF_PORT) or (r_port==SELF_PORT)
        key=(c.laddr.ip,c.laddr.port,c.pid,r_ip,r_port)
        pi=proc_cache.get(c.pid,{"name":"","user":"","exe":"","rss_mb":None,"parent":""})
        name=pi.get("name",""); user=pi.get("user",""); exe=pi.get("exe",""); rss_mb=pi.get("rss_mb",None); parent_txt=pi.get("parent","")
        first_seen.setdefault(key,now); age_s=float(now-first_seen[key])
        status=c.status or ""
        direction="LISTEN" if status=="LISTEN" else ("OUT" if r_ip else "IN")
        exe_missing=(not exe)
        exe_standard=bool(exe) and exe.startswith(STANDARD_EXE_PREFIXES)
        base_ctx={"pid":int(c.pid),"name":name,"user":user,"exe_path":exe or "","exe_missing":bool(exe_missing),"exe_standard":bool(exe_standard),
                  "lip":c.laddr.ip,"port":int(c.laddr.port),"rip":r_ip,"rport":int(r_port),"status":status,"dir":direction,
                  "age_s":age_s,"fanout":int(per_pid_total.get(c.pid,0)),"self":bool(is_self),"ip_publica":bool(r_ip and is_public_ip(r_ip))}
        alerts=apply_rules_fixpoint(base_ctx)
        severity=0
        for a in alerts:
            d=RULE_DEFS.get(a)
            if d: severity=max(severity,int(d.get("severity",1)))
        data[key]={"lip":base_ctx["lip"],"port":base_ctx["port"],"pid":base_ctx["pid"],"name":base_ctx["name"] or "(?)","parent":parent_txt,
                   "status":base_ctx["status"],"rip":base_ctx["rip"],"rport":base_ctx["rport"],"dir":base_ctx["dir"],"age_txt":fmt_age(age_s),
                   "user":base_ctx["user"] or "(?)","exe":base_ctx["exe_path"],"exe_short":short_path(base_ctx["exe_path"]),
                   "alerts":alerts,"self":base_ctx["self"],"severity":severity,"rss_mb":rss_mb}
    return data

def _push_event(kind,row,t,idx):
    global EVENT_SEQ
    EVENT_SEQ+=1
    ev={"id":EVENT_SEQ,"t":t,"type":kind,"pid":row.get("pid"),"name":row.get("name"),"port":row.get("port"),
        "rip":row.get("rip"),"rport":row.get("rport"),"status":row.get("status"),"alerts":row.get("alerts") or []}
    LOG_EVENTS.append(ev)
    if ev["alerts"]: LOG_ALERT_EVENTS.append(ev)
    m={"i":idx,"color":"#00ff00" if kind=="OPEN" else "#ff4444","t":t,"kind":"open" if kind=="OPEN" else "close",
       "pid":ev["pid"],"name":ev["name"],"port":ev["port"],"rip":ev["rip"],"rport":ev["rport"],"status":ev["status"],"ev":kind}
    net_marks.append(m); _append_tmp({"type":"mark",**m})

@app.route("/api/state")
def api_state():
    global last
    cur=snapshot()
    opened_keys=cur.keys()-last.keys()
    closed_keys=last.keys()-cur.keys()
    for k in closed_keys: first_seen.pop(k,None)
    opened=[cur[k] for k in opened_keys if not cur[k].get("self")]
    closed=[last[k] for k in closed_keys if not last[k].get("self")]
    ports=sorted(cur.values(),key=lambda x:(-x["severity"],x["port"],x["pid"],x["rip"],x["rport"]))
    t=now_ts()
    with net_lock:
        hist=list(net_hist)
        idx=len(hist)-1 if hist else 0
        for o in opened: _push_event("OPEN",o,t,idx)
        for c in closed: _push_event("CLOSE",c,t,idx)
        marks=list(net_marks)
    net={"tx_bps":0.0,"rx_bps":0.0,"tx":"0.0 B/s","rx":"0.0 B/s"} if not hist else {"tx_bps":float(hist[-1].get("tx_bps",0.0)),
        "rx_bps":float(hist[-1].get("rx_bps",0.0)),"tx":hist[-1].get("tx","0.0 B/s"),"rx":hist[-1].get("rx","0.0 B/s")}
    last=cur
    since=int(request.args.get("since","0") or "0")
    evs=[e for e in list(LOG_EVENTS) if int(e.get("id",0))>since]
    aevs=[e for e in list(LOG_ALERT_EVENTS) if int(e.get("id",0))>since]
    return jsonify({"ports":ports,"opened":opened,"closed":closed,"events":evs,"alert_events":aevs,"time":t,"net":net,"net_history":hist,"net_marks":marks,"net_tmp":NET_TMP_PATH,"alert_definitions":RULE_DEFS})

@app.route("/api/kill",methods=["POST"])
def api_kill(): kill_process(int(request.json["pid"])); return {"ok":True}

@app.route("/api/info/<int:pid>")
def api_info(pid): return proc_info(pid)

@app.route("/new.wav")
def new_wav():
    path=os.path.join(os.path.dirname(os.path.abspath(__file__)),"new.wav")
    if not os.path.exists(path): abort(404)
    return send_file(path,mimetype="audio/wav")

HTML=r"""<!doctype html><html><head><meta charset="utf-8"><title>Taskport</title><style>body{background:#0d0d0d;color:#eee;font-family:system-ui;font-size:12px;margin:10px}.header{display:flex;align-items:center;gap:10px;margin-bottom:6px}h2{margin:0;font-size:16px}.tag{padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid transparent}.tag.tx{color:#0ff;border-color:#0ff}.tag.rx{color:#ff9ecb;border-color:#ff9ecb}#netWrap{position:relative;margin-bottom:8px}#netChart{width:100%;height:100px;background:#000;border:1px solid #222;display:block}#tip{position:absolute;display:none;pointer-events:none;background:#000;border:1px solid #333;color:#eee;font:11px ui-monospace,monospace;padding:4px 6px;white-space:pre}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;padding:2px 6px;border-bottom:1px solid #222;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}th{background:#1a1a1a;font-weight:600}tr.new{background:#444;animation:fade 1.5s forwards}@keyframes fade{to{background:#0d0d0d}}tr.sev3 td{border-left:3px solid #a55}tr.sev2 td{border-left:3px solid #7a4}td.dirCell{position:relative;padding-left:10px}td.dirCell::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:#666}td.dir-out::before{background:#0ff}td.dir-in::before{background:#ff9ecb}td.dir-listen::before{background:#666}.badge{display:inline-block;padding:1px 6px;border:1px solid #333;border-radius:999px;font-size:11px;cursor:pointer;margin-right:4px;user-select:none}.badge.warn{border-color:#7a4;color:#cfc}.badge.alert{border-color:#a55;color:#fbb}.badge.info{border-color:#5fa9ff;color:#b7dcff}.status-LISTEN{color:#7fdfff}.status-ESTABLISHED{color:#7fff7f}.status-CLOSE_WAIT,.status-TIME_WAIT{color:#ffbf7f}.status-SYN_SENT,.status-SYN_RECV{color:#ffd27f}button{background:#333;color:#eee;border:none;padding:2px 6px;border-radius:6px}button:hover{background:#444}#log,#alertlog{height:160px;background:#000;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:11px;line-height:1.35;overflow:auto;white-space:pre;border:1px solid #222;padding:6px}#log{color:#0ff}#alertlog{color:#ff9800}.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:999}.modal-content{background:#111;padding:14px;width:min(920px,92vw);border:1px solid #222;border-radius:12px}pre{margin:0;overflow:auto;max-height:70vh;font-size:12px}.box{border:1px solid #222;border-radius:10px;padding:10px;margin:8px 0;background:#0f0f0f}.label{color:#aaa;font-size:11px;margin-bottom:4px}a.remoteLink{color:#b7dcff;text-decoration:none;border-bottom:1px dotted #5fa9ff}a.remoteLink:hover{border-bottom:1px solid #5fa9ff}.userRoot{color:#ffeb3b}</style></head><body><div class="header"><h2>Taskport</h2><span class="tag tx" id="txLbl">TX 0.0 B/s</span><span class="tag rx" id="rxLbl">RX 0.0 B/s</span></div><div id="netWrap"><canvas id="netChart"></canvas><div id="tip"></div></div><table><thead><tr><th style="width:48px">LPort</th><th style="width:58px">PID</th><th style="width:64px">RSS</th><th style="width:140px">Proceso</th><th style="width:160px">Padre</th><th style="width:190px">Remoto</th><th style="width:56px">Dir</th><th style="width:108px">Estado</th><th style="width:66px">Age</th><th style="width:140px">Usuario</th><th style="width:260px">Exe</th><th style="width:240px">Alertas</th><th style="width:116px">Acción</th></tr></thead><tbody id="rows"></tbody></table><h3 style="margin:10px 0 6px 0;font-size:14px">Log</h3><div id="log"></div><h3 style="margin:10px 0 6px 0;font-size:14px">Log alertas</h3><div id="alertlog"></div><div style="display:flex;gap:8px;align-items:center;margin-top:8px"><button onclick="unlock()">Activar sonido</button><audio id="snd" src="/new.wav"></audio></div><div class="modal" id="infoModal"><div class="modal-content"><pre id="infoText"></pre><div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="hideInfo()">Cerrar</button></div></div></div><div class="modal" id="alertModal"><div class="modal-content"><h3 id="a_title" style="margin:0 0 8px 0;font-size:14px"></h3><div class="box"><div class="label">Por qué es sospechoso</div><div id="a_why"></div></div><div class="box"><div class="label">Falsos positivos típicos</div><div id="a_fp"></div></div><div class="box"><div class="label">Qué mirar (rápido)</div><div id="a_what"></div></div><div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="hideAlert()">Cerrar</button></div></div></div><script>let unlocked=false,ALERT_DEFS={},hist=[],marks=[],procColors=Object.create(null),lastEventId=0;const $=s=>document.querySelector(s),snd=$("#snd"),canvas=$("#netChart"),ctx=canvas.getContext("2d"),tip=$("#tip");const randColor=()=>`hsl(${Math.floor(Math.random()*360)},90%,70%)`,colorFor=n=>procColors[n]||(procColors[n]=randColor());function unlock(){snd.play().catch(()=>{});unlocked=true}function resize(){canvas.width=canvas.clientWidth;canvas.height=canvas.clientHeight}addEventListener("resize",resize);resize();function drawChart(){ctx.clearRect(0,0,canvas.width,canvas.height);if(!hist.length)return;const tx=hist.map(p=>p.tx_bps||0),rx=hist.map(p=>p.rx_bps||0),ts=hist.map(p=>p.t||"");const max=Math.max(1,...tx,...rx),sx=canvas.width/Math.max(1,hist.length-1),sy=canvas.height/max;const line=(arr,color)=>{if(!arr.length)return;ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=1.5;arr.forEach((v,i)=>{const x=i*sx,y=canvas.height-(v*sy);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()};line(tx,"#0ff");line(rx,"#ff9ecb");marks.forEach(m=>{if(m.i<0||m.i>=hist.length)return;const x=m.i*sx;ctx.strokeStyle=m.color||"#666";ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,canvas.height);ctx.stroke()});ctx.fillStyle="#666";ctx.font="10px ui-monospace,monospace";for(let i=0;i<ts.length;i++)if(i%30===0){const x=i*sx;ctx.save();ctx.translate(x,canvas.height-2);ctx.rotate(-Math.PI/4);ctx.fillText(ts[i],0,0);ctx.restore()}}function idxFromMouse(ev){if(!hist.length)return-1;const r=canvas.getBoundingClientRect(),x=ev.clientX-r.left;const i=Math.round(x/canvas.width*(hist.length-1));return i<0||i>=hist.length?-1:i}function evLine(m){const k=m.ev==="OPEN"||m.kind==="open"?"ABRE":"CIERRA";const r=m.rip?`${m.rip}:${m.rport}`:"(local)";return`${m.t} ${k} LPort ${m.port} PID ${m.pid} ${m.name||"(?)"} -> ${r}`}canvas.addEventListener("mousemove",ev=>{const i=idxFromMouse(ev);if(i<0){tip.style.display="none";return}const tx=hist[i].tx_bps||0,rx=hist[i].rx_bps||0,t=hist[i].t||"";const sx=canvas.width/Math.max(1,hist.length-1),x=i*sx;const evs=marks.filter(m=>m.i===i);const extra=evs.length?"\n"+evs.map(evLine).join("\n"):"";tip.style.display="block";tip.style.left=x+8+"px";tip.style.top="10px";tip.textContent=`${t}\nTX ${tx.toFixed(1)} B/s  RX ${rx.toFixed(1)} B/s${extra}`;drawChart();const max=Math.max(1,...hist.map(p=>p.tx_bps||0),...hist.map(p=>p.rx_bps||0)),sy=canvas.height/max;ctx.fillStyle="#0ff";ctx.beginPath();ctx.arc(x,canvas.height-(tx*sy),2.5,0,Math.PI*2);ctx.fill();ctx.fillStyle="#ff9ecb";ctx.beginPath();ctx.arc(x,canvas.height-(rx*sy),2.5,0,Math.PI*2);ctx.fill()});canvas.addEventListener("mouseleave",()=>{tip.style.display="none";drawChart()});function logLine(s){const d=$("#log");d.textContent+=s+"\n";d.scrollTop=d.scrollHeight}function alertLogLine(s){const d=$("#alertlog");d.textContent+=s+"\n";d.scrollTop=d.scrollHeight}function showAlert(id){const def=ALERT_DEFS[id],title=def?def.badge||id:id,desc=def?def.description||{}:{};$("#a_title").textContent=title;$("#a_why").textContent=desc.why||"";$("#a_fp").textContent=desc.fp||"";$("#a_what").textContent=desc.what||"";$("#alertModal").style.display="flex"}function hideAlert(){$("#alertModal").style.display="none"}async function showInfo(pid){const r=await fetch("/api/info/"+pid);$("#infoText").textContent=JSON.stringify(await r.json(),null,2);$("#infoModal").style.display="flex"}function hideInfo(){$("#infoModal").style.display="none"}function badgeClass(id){const def=ALERT_DEFS[id],sev=def?def.severity??1:1;if(sev<=0)return"badge info";if(sev>=3)return"badge alert";if(sev===2)return"badge warn";return"badge info"}function badgeText(id){const def=ALERT_DEFS[id];return def&&def.badge?def.badge:id}function badges(arr){return!arr||!arr.length?"":arr.map(id=>`<span class="${badgeClass(id)}" data-alert="${id}" title="Click para explicación">${badgeText(id)}</span>`).join(" ")}document.addEventListener("click",ev=>{const el=ev.target;if(el?.dataset?.alert)return showAlert(el.dataset.alert);const ip=el?.dataset?.rip;if(ip)return window.open(`https://www.elhacker.net/geolocalizacion.html?host=${encodeURIComponent(ip)}`,"_blank","noopener")});function alertBadgesInline(alerts){if(!alerts||!alerts.length)return"";return alerts.map(a=>badgeText(a)).join(",")}async function refresh(){const r=await fetch("/api/state?since="+encodeURIComponent(lastEventId));const d=await r.json();ALERT_DEFS=d.alert_definitions||{};$("#txLbl").textContent=`TX ${d.net.tx}`;$("#rxLbl").textContent=`RX ${d.net.rx}`;hist=d.net_history||[];marks=d.net_marks||[];drawChart();(d.events||[]).forEach(e=>{if((e.id||0)>lastEventId)lastEventId=e.id||lastEventId;const remote=e.rip?`${e.rip}:${e.rport}`:"";const k=e.type==="OPEN"?"OPEN ":"CLOSE";logLine(`[${e.t}] ${k} LPort ${e.port} PID ${e.pid} ${e.name||"(?)"} ${e.status||""} ${remote}`.trim());if(unlocked&&e.type==="OPEN")snd.play().catch(()=>{})});(d.alert_events||[]).forEach(e=>{const remote=e.rip?`${e.rip}:${e.rport}`:"";const k=e.type==="OPEN"?"OPEN ":"CLOSE";const al=alertBadgesInline(e.alerts||[]);alertLogLine(`[${e.t}] ALERT ${k} LPort ${e.port} PID ${e.pid} ${e.name||"(?)"} ${e.status||""} ${remote} [${al}]`.trim())});const tb=$("#rows");tb.innerHTML="";for(const p of d.ports||[]){const tr=document.createElement("tr");if(p.severity===3)tr.classList.add("sev3");else if(p.severity===2)tr.classList.add("sev2");const isNew=!p.self&&(d.opened||[]).find(o=>o.pid===p.pid&&o.port===p.port&&(o.rip||"")===(p.rip||"")&&(o.rport||0)===(p.rport||0));if(isNew)tr.classList.add("new");const remoteTxt=p.rip?`${p.rip}:${p.rport}`:p.status==="LISTEN"?"(listen)":"(local)";const remoteCell=p.rip?`<a class="remoteLink" href="javascript:void(0)" data-rip="${p.rip}" title="Geolocalizar">${remoteTxt}</a>`:`<span title="${remoteTxt}">${remoteTxt}</span>`;const dirClass=p.dir==="OUT"?"dirCell dir-out":p.dir==="IN"?"dirCell dir-in":"dirCell dir-listen";const rssTxt=p.rss_mb==null?"-":Number(p.rss_mb).toFixed(1);const procColor=colorFor(p.name||"(?)");const userCls=p.user==="root"?"userRoot":"";tr.innerHTML=`<td>${p.port}</td><td>${p.pid}</td><td title="RSS (MB) memoria residente">${rssTxt}</td><td title="${p.name}" style="color:${procColor}">${p.name}</td><td title="${p.parent||""}">${p.parent||""}</td><td title="${remoteTxt}">${remoteCell}</td><td class="${dirClass}">${p.dir}</td><td class="status-${p.status}">${p.status}</td><td>${p.age_txt}</td><td class="${userCls}">${p.user}</td><td title="${p.exe||""}">${p.exe_short||""}</td><td>${badges(p.alerts)}</td><td><button onclick="showInfo(${p.pid})">Info</button> <button onclick="fetch('/api/kill',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:${p.pid}})})">Kill</button></td>`;tb.appendChild(tr)}}setInterval(refresh,2000);refresh();</script><div style="margin-top:10px;font-size:11px;color:#aaa;text-align:center">Taskport es un ejercicio de programación de <b style="color:#eee">JCRueda</b>. <a href="https://github.com/disketteomelette" target="_blank" rel="noopener" style="color:#fff;text-decoration:none;border-bottom:1px dotted #555">GitHub</a>. Licenciado bajo MIT-TAL.</div></body></html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

if __name__=="__main__":
    app.run("127.0.0.1", SELF_PORT, debug=False)

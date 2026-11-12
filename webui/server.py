#!/usr/bin/env python3
"""IRForge Web Console - local-only dashboard that runs irforge.exe and visualises its findings.

Pure standard library. Binds to 127.0.0.1. Never executes anything except irforge.exe with fixed verbs.
Usage: python server.py [--port 8787] [--no-browser]
"""
import argparse, collections, ipaddress, json, os, re, sqlite3, subprocess, sys, threading, time, webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"
OUT = ROOT / "out"
EXE_CANDIDATES = [ROOT / "build/mingw/irforge.exe", ROOT / "build/coverage/irforge.exe", ROOT / "build/mingw-debug/irforge.exe"]
FIXTURES = ROOT / "tests/fixtures"
RULESETS = {"internal": "rules/internal", "legacy": "rules"}

RUN = {"state": "idle", "proc": None, "log": [], "session": None, "mode": None, "started": None,
       "duration": 0, "exit_code": None, "cmd": None}
RUN_LOCK = threading.Lock()


def find_exe():
    for c in EXE_CANDIDATES:
        if c.exists():
            return c
    return None


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_json(p, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return default


def read_jsonl(p):
    out = []
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return out


def session_dir(name):
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    d = OUT / name
    return d if d.is_dir() and (d / "events.jsonl").exists() or (d.is_dir() and (d / "session-metadata.json").exists()) else None


def list_sessions():
    res = []
    if not OUT.exists():
        return res
    for d in OUT.iterdir():
        if not d.is_dir():
            continue
        meta = read_json(d / "session-metadata.json")
        ev = d / "events.jsonl"
        if not meta or not ev.exists():
            continue
        al = d / "alerts.jsonl"
        ids = set()
        top = 0
        for a in read_jsonl(al):
            ids.add(a.get("incident_id"))
            top = max(top, a.get("score", 0))
        res.append({"name": d.name, "mode": meta.get("mode"), "host": meta.get("host"), "result": meta.get("result"),
                    "start": meta.get("start_utc"), "events": sum(1 for _ in open(ev, "rb")),
                    "incidents": len(ids), "top_score": top, "mtime": ev.stat().st_mtime})
    res.sort(key=lambda s: -s["mtime"])
    return res


def latest_incidents(d):
    """Prefer SQLite incident documents (richer, includes ATT&CK); fall back to alerts.jsonl."""
    incs = {}
    db = d / "irforge.sqlite"
    if db.exists():
        try:
            c = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=1)
            for iid, status, sev, score, upd, rev, doc in c.execute(
                    "select id,status,severity,score,updated_ms,revision,document from incidents"):
                j = json.loads(doc)
                j.update({"incident_id": iid, "status": status, "severity": sev, "score": score, "revision": rev})
                j.setdefault("local_incident_id", iid)
                incs[iid] = j
            c.close()
        except Exception:
            incs = {}
    if not incs:
        for a in read_jsonl(d / "alerts.jsonl"):
            incs[a.get("incident_id")] = a  # later snapshots supersede
    out = []
    for k, v in incs.items():
        v.setdefault("incident_id", k)
        v.setdefault("score", v.get("risk_score", 0))
        out.append(v)
    out.sort(key=lambda i: -i.get("score", 0))
    return out


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast)
    except Exception:
        return False


def base(path):
    if not path:
        return "?"
    return re.split(r"[\\/]", path)[-1] or path


def build_summary(d):
    events = read_jsonl(d / "events.jsonl")
    meta = read_json(d / "session-metadata.json", {})
    health = read_json(d / "monitor-health.json", {})
    incidents = latest_incidents(d)

    types = collections.Counter(e.get("event_type") for e in events)
    sources = collections.Counter(e.get("source") for e in events)
    procs, names = {}, {}
    for e in events:
        if e.get("event_type") == "process_start":
            p = e.get("payload", {})
            pid = p.get("identity", {}).get("pid")
            procs[pid] = p
            names[pid] = base(p.get("image_path"))
    remote = collections.Counter()
    conns = 0
    states = collections.Counter()
    for e in events:
        if e.get("event_type") == "tcp_connection_observed":
            p = e["payload"]
            if p.get("state") != "LISTEN":
                conns += 1
                remote[p.get("remote_address")] += 1
            states[p.get("state")] += 1
    ts = [e.get("timestamp_utc") for e in events if e.get("timestamp_utc")]
    buckets = []
    if ts:
        def parse(s):
            return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        t0, t1 = parse(min(ts)), parse(max(ts))
        n = 48
        span = max(t1 - t0, 1)
        cats = {"process": [0] * n, "network": [0] * n, "registry": [0] * n, "other": [0] * n}
        for e in events:
            try:
                i = min(int((parse(e["timestamp_utc"]) - t0) / span * n), n - 1)
            except Exception:
                continue
            ty = e.get("event_type", "")
            k = "process" if ty.startswith("process") else "network" if ty.startswith("tcp") else \
                "registry" if "registry" in ty else "other"
            cats[k][i] += 1
        buckets = {"t0": min(ts), "t1": max(ts), "series": cats}
    top_proc = collections.Counter()
    for e in events:
        if e.get("event_type") == "tcp_connection_observed" and e["payload"].get("state") != "LISTEN":
            top_proc[names.get(e["payload"].get("owner_pid"), "pid %s" % e["payload"].get("owner_pid"))] += 1
    sev = collections.Counter(i.get("severity") for i in incidents)
    tech = {}
    for i in incidents:
        for t in i.get("attack_techniques", []) or []:
            tech.setdefault(t["id"], {"id": t["id"], "name": t.get("name"), "tactics": t.get("tactics", []), "count": 0})["count"] += 1
        for m in i.get("matched_rules", []):
            for t in m.get("attack", []) or []:
                tech.setdefault(t, {"id": t, "name": None, "tactics": [], "count": 0})
    return {
        "name": d.name, "meta": meta, "health": health,
        "kpi": {"events": len(events), "processes": len(procs), "connections": conns,
                "public_remotes": sum(1 for r in remote if is_public(r)), "incidents": len(incidents),
                "listening": states.get("LISTEN", 0), "exits": types.get("process_exit", 0)},
        "types": types, "sources": sources, "severity": sev, "timeline": buckets,
        "top_remote": [{"ip": ip, "count": c, "public": is_public(ip)} for ip, c in remote.most_common(10)],
        "top_net_procs": top_proc.most_common(8), "techniques": list(tech.values()),
        "incidents": [slim_incident(i) for i in incidents],
    }


def slim_incident(i):
    return {k: i.get(k) for k in ("incident_id", "local_incident_id", "title", "severity", "score", "confidence", "status",
                                  "first_seen_utc", "last_seen_utc", "rule_ids", "attack_techniques")} | {
        "rules": len(i.get("matched_rules", []))}


def incident_detail(d, iid):
    inc = next((i for i in latest_incidents(d) if i["incident_id"] == iid), None)
    if not inc:
        return None
    ids = set(inc.get("evidence_event_ids") or inc.get("event_ids") or [])
    evs = [e for e in read_jsonl(d / "events.jsonl") if e.get("event_id") in ids]
    return {"incident": inc, "events": evs}


def event_label(e):
    p = e.get("payload", {})
    t = e.get("event_type")
    if t in ("process_start", "process_exit"):
        return p.get("command_line") or p.get("image_path") or ""
    if t and t.startswith("tcp"):
        return "%s:%s → %s:%s  %s" % (p.get("local_address"), p.get("local_port"), p.get("remote_address"), p.get("remote_port"), p.get("state"))
    if t == "monitor_status":
        return "%s — %s" % (p.get("state"), (p.get("message") or "").strip())
    return json.dumps(p)[:300]


def query_events(d, q):
    typ = q.get("type", [""])[0]
    text = q.get("q", [""])[0].lower()
    off = int(q.get("offset", ["0"])[0])
    lim = min(int(q.get("limit", ["100"])[0]), 500)
    hide_status = q.get("hide_status", ["1"])[0] == "1"
    events = read_jsonl(d / "events.jsonl")
    names = {}
    for e in events:
        if e.get("event_type") == "process_start":
            names[e["payload"]["identity"]["pid"]] = base(e["payload"].get("image_path"))
    rows = []
    for e in events:
        t = e.get("event_type")
        if hide_status and t == "monitor_status":
            continue
        if typ and t != typ:
            continue
        p = e.get("payload", {})
        label = event_label(e)
        pid = p.get("identity", {}).get("pid") or p.get("owner_pid")
        proc = base(p.get("image_path")) if p.get("image_path") else names.get(pid, "")
        if text and text not in (label + proc + str(pid) + str(t)).lower():
            continue
        rows.append({"id": e.get("event_id"), "ts": e.get("timestamp_utc"), "type": t, "source": e.get("source"),
                     "pid": pid, "proc": proc, "label": label, "raw": e})
    rows.reverse()
    return {"total": len(rows), "rows": rows[off:off + lim]}


def process_table(d):
    events = read_jsonl(d / "events.jsonl")
    procs, exits, netcount = {}, {}, collections.Counter()
    for e in events:
        p = e.get("payload", {})
        t = e.get("event_type")
        pid = p.get("identity", {}).get("pid")
        if t == "process_start":
            procs[pid] = {"pid": pid, "ppid": p.get("parent_pid"), "name": base(p.get("image_path")), "path": p.get("image_path"),
                          "cmd": p.get("command_line"), "start": e.get("timestamp_utc"), "initial": p.get("initial_enumeration"), "event_id": e.get("event_id")}
        elif t == "process_exit":
            exits[pid] = e.get("timestamp_utc")
        elif t == "tcp_connection_observed" and p.get("state") != "LISTEN":
            netcount[p.get("owner_pid")] += 1
    flagged = set()
    for i in latest_incidents(d):
        for ident in i.get("linked_process_identities", []):
            flagged.add(ident.get("pid"))
    for pid, r in procs.items():
        r["exited"] = exits.get(pid)
        r["conns"] = netcount.get(pid, 0)
        r["flagged"] = pid in flagged
    return sorted(procs.values(), key=lambda r: (not r["flagged"], -(r["conns"]), r["pid"] or 0))


def network_table(d):
    events = read_jsonl(d / "events.jsonl")
    names = {}
    for e in events:
        if e.get("event_type") == "process_start":
            names[e["payload"]["identity"]["pid"]] = base(e["payload"].get("image_path"))
    seen = {}
    for e in events:
        if e.get("event_type") in ("tcp_connection_observed", "tcp_connection_closed"):
            p = e["payload"]
            key = (p.get("local_address"), p.get("local_port"), p.get("remote_address"), p.get("remote_port"), p.get("owner_pid"))
            r = seen.setdefault(key, {"local": f"{p.get('local_address')}:{p.get('local_port')}",
                                      "remote": f"{p.get('remote_address')}:{p.get('remote_port')}",
                                      "remote_ip": p.get("remote_address"), "pid": p.get("owner_pid"),
                                      "proc": names.get(p.get("owner_pid"), ""), "state": p.get("state"),
                                      "first": e.get("timestamp_utc"), "closed": False,
                                      "public": is_public(p.get("remote_address")), "proto": p.get("protocol")})
            r["last"] = e.get("timestamp_utc")
            if e["event_type"] == "tcp_connection_closed":
                r["closed"] = True
    return sorted(seen.values(), key=lambda r: (r["state"] == "LISTEN", not r["public"], r["proc"]))


# ---------------------------------------------------------------- run control
def start_run(body):
    exe = find_exe()
    if not exe:
        return {"error": "irforge.exe not found. Build it first (scripts/build.ps1)."}, 400
    with RUN_LOCK:
        if RUN["state"] == "running":
            return {"error": "A run is already in progress."}, 409
        mode = body.get("mode", "monitor")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        rules = RULESETS.get(body.get("rules", "internal"), "rules/internal")
        if mode == "replay":
            fx = body.get("fixture", "suspicious_chain.jsonl")
            if "/" in fx or "\\" in fx or not (FIXTURES / fx).exists():
                return {"error": "Unknown fixture."}, 400
            name = f"web-replay-{stamp}"
            cmd = [str(exe), "replay", "--events", str(FIXTURES / fx), "--rules", str(ROOT / rules), "--output", str(OUT / name)]
            dur = 0
        else:
            dur = max(5, min(int(body.get("duration", 30)), 3600))
            name = f"web-live-{stamp}"
            cmd = [str(exe), "monitor", "--config", str(ROOT / "config/default.json"), "--rules", str(ROOT / rules),
                   "--output", str(OUT / name), "--duration-seconds", str(dur), "--allow-degraded"]
        OUT.mkdir(exist_ok=True)
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        RUN.update(state="running", proc=proc, log=["$ " + " ".join(Path(c).name if i == 0 else c for i, c in enumerate(cmd))],
                   session=name, mode=mode, started=time.time(), duration=dur, exit_code=None, cmd=cmd)
        threading.Thread(target=pump, args=(proc,), daemon=True).start()
        return {"session": name}, 200


def pump(proc):
    for raw in iter(proc.stdout.readline, b""):
        line = raw.decode("utf-8", "replace").rstrip()
        if line:
            RUN["log"].append(line)
            del RUN["log"][:-300]
    code = proc.wait()
    with RUN_LOCK:
        if RUN["state"] != "stopped":
            RUN["state"] = "done"
        RUN["exit_code"] = code


def stop_run():
    with RUN_LOCK:
        p = RUN.get("proc")
        if RUN["state"] == "running" and p:
            RUN["state"] = "stopped"
            p.terminate()
    return {"ok": True}


def run_status():
    return {k: RUN[k] for k in ("state", "log", "session", "mode", "started", "duration", "exit_code")} | {
        "elapsed": (time.time() - RUN["started"]) if RUN["started"] and RUN["state"] == "running" else None}


def env_info():
    exe = find_exe()
    ver = ""
    if exe:
        try:
            ver = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            pass
    return {"exe": str(exe) if exe else None, "version": ver, "admin": is_admin(), "root": str(ROOT),
            "fixtures": sorted(p.name for p in FIXTURES.glob("*.jsonl")) if FIXTURES.exists() else [],
            "rulesets": list(RULESETS)}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, obj, code=200, ctype="application/json"):
        data = obj if isinstance(obj, bytes) else json.dumps(obj, default=list).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(data)

    def host_ok(self):
        return (self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost"))

    def do_GET(self):
        if not self.host_ok():
            return self.send({"error": "forbidden"}, 403)
        u = urlparse(self.path)
        parts = [unquote(p) for p in u.path.strip("/").split("/")]
        q = parse_qs(u.query)
        try:
            if parts[0] == "api":
                if parts[1:] == ["env"]:
                    return self.send(env_info())
                if parts[1:] == ["sessions"]:
                    return self.send(list_sessions())
                if parts[1:] == ["run"]:
                    return self.send(run_status())
                if parts[1] == "session" and len(parts) >= 4:
                    d = session_dir(parts[2])
                    if not d:
                        return self.send({"error": "not found"}, 404)
                    what = parts[3]
                    if what == "summary":
                        return self.send(build_summary(d))
                    if what == "events":
                        return self.send(query_events(d, q))
                    if what == "processes":
                        return self.send(process_table(d))
                    if what == "network":
                        return self.send(network_table(d))
                    if what == "incident" and len(parts) >= 5:
                        r = incident_detail(d, "/".join(parts[4:]))
                        return self.send(r) if r else self.send({"error": "not found"}, 404)
                return self.send({"error": "not found"}, 404)
            f = "index.html" if u.path == "/" else u.path.lstrip("/")
            p = (STATIC / f).resolve()
            if STATIC not in p.parents or not p.is_file():
                return self.send({"error": "not found"}, 404)
            ct = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}.get(p.suffix, "application/octet-stream")
            return self.send(p.read_bytes(), 200, ct)
        except Exception as ex:  # keep server alive
            return self.send({"error": str(ex)}, 500)

    def do_POST(self):
        if not self.host_ok() or self.headers.get("X-IRForge") != "1":
            return self.send({"error": "forbidden"}, 403)
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        path = urlparse(self.path).path
        if path == "/api/run/start":
            r, c = start_run(body)
            return self.send(r, c)
        if path == "/api/run/stop":
            return self.send(stop_run())
        self.send({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{a.port}/"
    print(f"IRForge Web Console → {url}   (exe: {find_exe()})")
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

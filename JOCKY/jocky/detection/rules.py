"""Extra defensive, read-only detection rules for the GUI (additive: process_detector.py is unchanged).

Rules: known tool names (original detector) + execution from user-writable paths + uncommon remote ports
+ persistence entries pointing to writable paths. Plus a simple risk score.
"""
import hashlib
import ipaddress
import re

from jocky.detection.process_detector import detect_suspicious_processes

WRITABLE = ("\\temp\\", "/tmp/", "/dev/shm", "\\downloads\\", "/.cache/", "/.config/autostart")
COMMON_PORTS = {80, 443, 53, 22, 123, 143, 465, 587, 993, 995, 5228, 8080, 8443}
POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 3}


def _f(host, rule, sev, target, reason):
    fid = hashlib.md5(f"{host}|{rule}|{target}".encode()).hexdigest()[:10].upper()
    return {"id": f"ALERT-{fid}", "host": host, "rule": rule, "severity": sev, "target": target, "reason": reason}


def writable(path):
    return any(t in (path or "").lower() for t in WRITABLE)


def run_all(data: dict, host: str) -> list[dict]:
    procs, conns, pers = data.get("processes", []), data.get("connections", []), data.get("persistence", [])
    out = [_f(host, "suspicious_process_name", f["severity"], f"{f['name']}:{f['executable']}",
              f"{f['name']} (PID {f['pid']}): {f['reason']}") for f in detect_suspicious_processes(procs)]
    for p in procs:
        if writable(p.get("executable")):
            out.append(_f(host, "exec_from_writable_path", "medium", f"{p['name']}:{p['executable']}",
                          f"{p['name']} (PID {p['pid']}) runs from user-writable path {p['executable']}"))
    seen = set()
    for c in conns:
        ra = c.get("remote_address") or ""
        if c.get("status") != "ESTABLISHED" or ":" not in ra:
            continue
        ip, port = ra.rsplit(":", 1)
        try:
            if not ipaddress.ip_address(ip).is_global or int(port) in COMMON_PORTS:
                continue
        except ValueError:
            continue
        k = (c.get("process"), port)
        if k not in seen:
            seen.add(k)
            out.append(_f(host, "uncommon_remote_port", "low", f"{c.get('process')}:{port}",
                          f"{c.get('process') or 'PID ' + str(c.get('pid'))} connected to {ra} (uncommon port)"))
    for e in pers:
        text = " ".join(str(e.get(k, "")) for k in ("location", "name", "data"))
        m = re.search(r"[^\"' ,]*(?:%s)[^\"' ,]*" % "|".join(re.escape(t) for t in WRITABLE), text, re.I)
        if m:
            out.append(_f(host, "persistence_writable_path", "high", f"{e.get('type')}:{m.group(0)}",
                          f"Persistence ({e.get('type')}) points to user-writable path {m.group(0)}"))
    return out


def score(findings: list[dict]) -> dict:
    s = min(100, sum(POINTS.get(f["severity"], 0) for f in findings))
    return {"score": s, "level": "LOW" if s <= 30 else "MEDIUM" if s <= 60 else "HIGH" if s <= 80 else "CRITICAL"}

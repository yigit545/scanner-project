#!/usr/bin/env python3
# app.py
# DarkScanner — simple ethical port scanner backend (safe-by-default)
# Requires: Python 3.8+
# Usage: python3 app.py

import asyncio
import socket
import time
import csv
import os
import tempfile
import threading
import ipaddress
from flask import Flask, jsonify, request, send_file, abort, Response

app = Flask(__name__, static_folder='.', static_url_path='')

# jobs storage (in-memory; for production use a persistent DB)
jobs = {}
job_lock = threading.Lock()

# Allowed networks (safe-by-default): localhost + RFC1918
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

# Helpers
def resolve_host(target):
    """Resolve hostname to IPv4 address (raises socket.gaierror on fail)."""
    return socket.gethostbyname(target)

def ip_is_allowed(ip_str):
    ip = ipaddress.ip_address(ip_str)
    for net in ALLOWED_NETWORKS:
        if ip in net:
            return True
    return False

def parse_ports(ports_str):
    """Parse ports like '80,443,8000-8010' or '1-1024' or '' -> common ports"""
    if not ports_str or ports_str.strip()=='':
        return [21,22,23,25,53,80,110,139,143,443,465,587,3306,3389,8080]
    parts = [p.strip() for p in ports_str.split(',') if p.strip()]
    out = set()
    for p in parts:
        if '-' in p:
            a,b = p.split('-',1)
            out.update(range(int(a), int(b)+1))
        else:
            out.add(int(p))
    return sorted(p for p in out if 1 <= p <= 65535)

# Async scanner
async def scan_port(ip, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception as e:
        return None  # closed / filtered
    banner = ""
    try:
        # Try to read a banner (some services send data immediately)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
            if data:
                banner += data.decode(errors='ignore').strip()
        except asyncio.TimeoutError:
            pass

        # If no banner and port looks HTTP, send a HEAD
        if not banner and port in (80, 8080, 8000, 8888):
            try:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n")
                await writer.drain()
                data2 = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                if data2:
                    banner += data2.decode(errors='ignore').splitlines()[0][:200]
            except Exception:
                pass
        # Limit banner length
        banner = banner[:500]
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return {"port": port, "banner": banner}

async def run_scan_job(job):
    """job: dict with id, ip, ports, timeout, workers"""
    ip = job["ip"]
    ports = job["ports"]
    timeout = float(job.get("timeout", 1.0))
    workers = int(job.get("workers", 50))
    job["status"] = "running"
    start = time.time()
    log_lines = []
    open_ports = []
    sem = asyncio.Semaphore(workers)

    async def sem_scan(p):
        async with sem:
            log_lines.append(f"Scanning {ip}:{p} ...")
            res = await scan_port(ip, p, timeout)
            if res:
                open_ports.append(res)
                log_lines.append(f"OPEN {p} {res['banner'][:80]}")
            else:
                log_lines.append(f"closed/filtered {p}")

    tasks = [asyncio.create_task(sem_scan(p)) for p in ports]
    # run all
    await asyncio.gather(*tasks)
    elapsed = time.time() - start
    job["open"] = sorted(open_ports, key=lambda x: x["port"])
    job["status"] = "done"
    job["elapsed"] = elapsed
    job["log"] = log_lines

def start_scan_async(job_id):
    job = jobs[job_id]
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_scan_job(job))
    loop.close()

# Routes
@app.route('/')
def index():
    return app.send_static_file('html.html')

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.json or {}
    target = (data.get("target") or "").strip()
    ports = data.get("ports","")
    timeout = float(data.get("timeout", 1.0))
    workers = int(data.get("workers", 50))

    if not target:
        return jsonify(ok=False, error="empty target"), 400

    # Resolve
    try:
        ip = resolve_host(target if not target.startswith("http") else target.split("://",1)[1].split("/")[0])
    except Exception as e:
        return jsonify(ok=False, error=f"resolve_failed: {e}"), 400

    if not ip_is_allowed(ip):
        return jsonify(ok=False, error=f"target_not_allowed ({ip}) — only localhost/private ranges allowed by default"), 403

    parsed_ports = parse_ports(ports)
    # limit workers to reasonable amount
    workers = max(1, min(workers, 500))

    with job_lock:
        job_id = str(len(jobs) + 1)
        jobs[job_id] = {
            "id": job_id,
            "target": target,
            "ip": ip,
            "ports": parsed_ports,
            "timeout": timeout,
            "workers": workers,
            "status": "queued",
            "start": time.time(),
            "open": [],
            "log": []
        }
    # start background thread
    t = threading.Thread(target=start_scan_async, args=(job_id,), daemon=True)
    t.start()
    return jsonify(ok=True, job_id=job_id)

@app.route('/api/jobs')
def api_jobs():
    with job_lock:
        jlist = []
        for jid, j in jobs.items():
            jlist.append({
                "id": j["id"],
                "target": j["target"],
                "status": j.get("status","idle"),
                "open_count": len(j.get("open",[]))
            })
    return jsonify(jobs=jlist)

@app.route('/api/status/<job_id>')
def api_status(job_id):
    j = jobs.get(job_id)
    if not j:
        return jsonify(ok=False, error="no such job"), 404
    # build response similar to frontend expectation
    return jsonify(ok=True, job={
        "id": j["id"],
        "target": j["target"],
        "ip": j.get("ip"),
        "status": j.get("status"),
        "elapsed": j.get("elapsed", 0.0),
        "open": j.get("open", []),
    })

@app.route('/api/log/<job_id>')
def api_log(job_id):
    j = jobs.get(job_id)
    if not j:
        return jsonify(ok=False, error="no such job"), 404
    return jsonify(ok=True, lines=j.get("log", []))

@app.route('/api/download/<job_id>')
def api_download(job_id):
    j = jobs.get(job_id)
    if not j:
        return jsonify(ok=False, error="no such job"), 404
    if j.get("status") != "done":
        return jsonify(ok=False, error="job not done"), 400
    # create CSV
    fd, path = tempfile.mkstemp(prefix=f"darkscanner_{job_id}_", suffix=".csv")
    os.close(fd)
    with open(path, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["port","banner"])
        for o in j.get("open", []):
            writer.writerow([o.get("port"), o.get("banner","")])
    return send_file(path, as_attachment=True, download_name=f"scan_{job_id}.csv")

if __name__ == '__main__':
    # dev server
    app.run(host='0.0.0.0', port=8000, debug=True)

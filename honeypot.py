"""
Honeypot Server - Lernprojekt für Cybersecurity
================================================
Simuliert eine verwundbare Webanwendung, 
loggt Angreifer-Verhalten
und analysiert Angriffsmuster.

"""

import http.server
import json
import logging
import os
import re
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime
from urllib.parse import unquote_plus, urlparse
import urllib.request


#Logging Setup

LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", "honeypot.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("honeypot")

MAX_REQUEST_BODY = 16 * 1024
LOGIN_WINDOW_SECONDS = 30
LOGIN_BRUTEFORCE_THRESHOLD = 3


#Fake-Daten (locken Angreifer)

FAKE_DATA = {
    "customers": [
        {"id": 1, "name": "Max Mustermann", "email": "max@example.com", "balance": 14200},
        {"id": 2, "name": "Anna Schmidt",   "email": "anna@example.com", "balance": 8750},
        {"id": 3, "name": "Klaus Weber",    "email": "k.weber@example.com", "balance": 32100},
    ],
    "config": {
        "db_host": "internal-db.example.local",
        "db_user": "app_user",
        "db_pass": "THIS_IS_FAKE_DATA_NOT_REAL",   # absichtlich sichtbar
        "api_key": "FAKE-KEY-9x2k-honeypot-trap",
    },
    "admin": {
        "username": "admin",
        "password_hash": "$2b$12$FAKEHASH_NOT_REAL_honeypot_trap",
        "role": "superadmin",
    },
}

# Bekannte Angriffs-Signaturen
ATTACK_PATTERNS = {
    "sql_injection": re.compile(
        r"(union|select|insert|drop|'--|;--|1\s*=\s*1|or\s+1|or\s+['\"]*[^=\s]*['\"]*\s*=)",
        re.I,
    ),
    "xss": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\\)", re.I),
    "command_injection": re.compile(
        r"(;|\||\$\(|`|&&|\|\|)\s*(ls|cat|id|whoami|uname|cmd)",
        re.I,
    ),
}

LOGIN_PATHS = {"/admin/login", "/login", "/auth"}


def detect_attack_patterns(path: str, body: str = "") -> list[str]:
    """Detect stateless attack signatures in a URL and request body."""
    combined = f"{unquote_plus(path)} {unquote_plus(body)}"
    return [
        name
        for name, pattern in ATTACK_PATTERNS.items()
        if pattern.search(combined)
    ]


#Angriffs-Tracker (In-Memory)

class AttackTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests_by_ip: dict[str, list] = defaultdict(list)
        self.attacks: list[dict] = []
        self.login_attempts: dict[str, deque[float]] = defaultdict(deque)

    def record(self, ip: str, entry: dict):
        with self.lock:
            self.requests_by_ip[ip].append(entry)
            if entry.get("attack_types"):
                self.attacks.append(entry)

    def record_login_attempt(self, ip: str, now: float | None = None) -> bool:
        """Return True after repeated login attempts inside the configured window."""
        current_time = time.monotonic() if now is None else now
        cutoff = current_time - LOGIN_WINDOW_SECONDS

        with self.lock:
            attempts = self.login_attempts[ip]
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            attempts.append(current_time)
            return len(attempts) >= LOGIN_BRUTEFORCE_THRESHOLD

    def get_stats(self) -> dict:
        with self.lock:
            total = sum(len(v) for v in self.requests_by_ip.values())
            attack_types = Counter(
                attack_type
                for entry in self.attacks
                for attack_type in entry.get("attack_types", [])
            )
            return {
                "unique_ips": len(self.requests_by_ip),
                "total_requests": total,
                "total_attacks": len(self.attacks),
                "attack_types": dict(attack_types),
                "top_attackers": sorted(
                    ((ip, len(reqs)) for ip, reqs in self.requests_by_ip.items()),
                    key=lambda x: x[1],
                    reverse=True,
                )[:5],
            }


tracker = AttackTracker()


#Request Handler

class HoneypotHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.2.14"
    sys_version = "(Ubuntu)"

    def log_message(self, format, *args):
        pass  # Standard-Logging unterdrücken, wir loggen selbst

    def log_request_details(self, method: str, body: str = ""):
        """Strukturiertes Logging aller relevanten Request-Infos."""
        ip = self.client_address[0]
        
        # TEST-MODUS ANFANG
        # Wenn der Angriff von uns selbst kommt, simulieren wir IPs aus aller Welt
        if ip == "127.0.0.1":
            import random
            test_ips = [
                "8.8.8.8",        # USA (Google)
                "1.1.1.1",        # Australien (Cloudflare)
                "193.99.144.80",  # Deutschland
                "210.130.120.40", # Japan
                "177.43.255.255", # Brasilien
                "196.25.255.250"  # Südafrika
            ]
            ip = random.choice(test_ips)
        # TEST-MODUS ENDE
        
        path = self.path
        user_agent = self.headers.get("User-Agent", "unknown")
        attack_types = detect_attack_patterns(path, body)
        normalized_path = urlparse(path).path.rstrip("/")

        if method == "POST" and normalized_path in LOGIN_PATHS:
            if tracker.record_login_attempt(ip):
                attack_types.append("login_bruteforce")

        # Geo-Daten abrufen
        geo_data = get_geo_info(ip)
        
        entry = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "ip": ip,
            "method": method,
            "path": path,
            "user_agent": user_agent,
            "body_snippet": body[:200] if body else None,
            "attack_types": attack_types, 
            "geo": geo_data #Geo-Daten ins Log schreiben
        }

        tracker.record(ip, entry)

        # Farbige Konsolen-Ausgabe
        flag = "[ANGRIFF]" if attack_types else "[ANFRAGE]"
        attack_str = f" [{', '.join(attack_types)}]" if attack_types else ""
        print(f"{flag}{attack_str}  {ip}  {method} {path}")

        # JSON ins Log-File
        logger.info(json.dumps(entry))
        return entry

    def send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.log_request_details("GET")
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        routes = {
            "":                  lambda: self.send_json(200, {"app": "CustomerPortal v2.1", "status": "ok"}),
            "/health":           lambda: self.send_json(200, {"status": "healthy"}),
            "/api/customers":    lambda: self.send_json(200, {"data": FAKE_DATA["customers"]}),
            "/api/admin":        lambda: self.send_json(200, FAKE_DATA["admin"]),
            "/api/config":       lambda: self.send_json(200, FAKE_DATA["config"]),
            "/admin":            lambda: self.send_json(200, {"message": "Admin panel", "hint": "Try /admin/login"}),
            "/admin/login":      lambda: self.send_json(200, {"form": "POST credentials to /admin/login"}),
            "/stats":            lambda: self.send_json(200, tracker.get_stats()),
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self.send_json(404, {"error": "Not found", "path": path})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return

        if length < 0:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return

        if length > MAX_REQUEST_BODY:
            self.send_json(413, {"error": "Request body too large"})
            return

        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        self.log_request_details("POST", body)

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in LOGIN_PATHS:
            # Simuliert fehlgeschlagenen Login (lockt zu weiteren Versuchen)
            time.sleep(0.5)  # Künstliche Verzögerung wie echtes System
            self.send_json(401, {"error": "Invalid credentials", "attempts_remaining": 3})

        elif path in ("/api/customers", "/api/data"):
            self.send_json(200, {"created": True, "id": 9999})

        else:
            self.send_json(404, {"error": "Endpoint not found"})


#Start

def run(host: str | None = None, port: int | None = None):
    host = host or os.getenv("HONEYPOT_HOST", "127.0.0.1")
    port = port if port is not None else int(os.getenv("HONEYPOT_PORT", "8080"))
    server = http.server.ThreadingHTTPServer((host, port), HoneypotHandler)
    print(f"""
Honeypot Server gestartet
   URL:   http://{host}:{port}
   Logs:  {LOG_FILE}
   Stats: http://{host}:{port}/stats

Verfügbare Endpunkte (für Tests):
  GET  /health          → Systemstatus
  GET  /api/customers    → Fake-Kundendaten
  GET  /api/admin        → Fake-Admin-Credentials
  GET  /api/config       → Fake-Konfiguration
  POST /admin/login      → Simulierter Login
  GET  /stats            → Angriffs-Statistiken
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer gestoppt.")
        print("\nFinale Statistiken:")
        stats = tracker.get_stats()
        print(json.dumps(stats, indent=2))
        
# Cache, damit wir dieselbe IP nicht 100x abfragen und geblockt werden
GEO_CACHE = {}

def get_geo_info(ip: str) -> dict:
    # Lokale IPs ignorieren
    if ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        return {"country": "Localhost", "lat": 47.2, "lon": 15.1} # Z.B. Steiermark als Fallback

    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    try:
        # ip-api.com liefert JSON mit Land, Lat und Lon
        url = f"http://ip-api.com/json/{ip}?fields=country,lat,lon"
        req = urllib.request.Request(url, headers={'User-Agent': 'Honeypot-Project/1.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read())
            if data:
                GEO_CACHE[ip] = data
                return data
    except Exception as e:
        pass # Fehler ignorieren, dann gibt es halt keine Karte für diese IP

    return {}


if __name__ == "__main__":
    run()

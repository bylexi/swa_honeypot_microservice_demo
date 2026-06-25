# HTTP-Honeypot Microservice

> Simuliert eine verwundbare Webanwendung, loggt Angreifer-Verhalten und analysiert Angriffsmuster.
> Das Projekt implementiert einen einzelnen Honeypot, kein vollständiges Honeynet.

---

## Quickstart

```bash
# 1. Honeypot starten
python3 honeypot.py

# 2. Angriffe simulieren (neues Terminal)
python3 attacker_sim.py

# 3. Logs auswerten
python3 log_analyzer.py
```

Dann im Browser öffnen:

- Status: `http://127.0.0.1:8080/health`
- Statistiken: `http://127.0.0.1:8080/stats`

---

## Projektstruktur

```
honeypot/
├── honeypot.py        # Honeypot-Server (HTTP, Port 8080)
├── dashboard.py       # Live-Dashboard mit Geo-IP-Karte
├── threat_scoring.py  # Risk-Scoring pro IP-Adresse
├── attacker_sim.py    # Angriffs-Simulator für Tests
├── log_analyzer.py    # Log-Auswertung & Threat Report
├── tests/             # Automatische Tests
├── honeypot.log       # Wird automatisch erstellt (JSON-Lines)
└── README.md          # Diese Datei
```

---

## Voraussetzungen

- Python 3.10+ (keine externen Packages nötig — nur Stdlib)
- Windows / macOS / Linux

Tests ausführen:

```bash
python3 -m unittest discover -s tests -v
```

---

## Endpunkte

| Methode | Pfad             | Beschreibung                        |
|---------|------------------|-------------------------------------|
| GET     | `/`              | App-Info (Fake-Server-Version)      |
| GET     | `/health`        | Status des Microservices            |
| GET     | `/api/customers` | Fake-Kundendaten (JSON)             |
| GET     | `/api/admin`     | Fake-Admin-Credentials (Köder)      |
| GET     | `/api/config`    | Fake-Konfiguration mit DB-Keys      |
| GET     | `/admin`         | Fake-Adminbereich                   |
| POST    | `/admin/login`   | Simulierter Login (immer 401)       |
| GET     | `/stats`         | **Echtzeit-Statistiken des Honeypots** |

---

## Erkannte Angriffs-Typen

| Typ                 | Beispiel-Payload                          |
|---------------------|-------------------------------------------|
| SQL Injection        | `?id=1 OR 1=1--` / `UNION SELECT *`      |
| XSS                 | `<script>alert(1)</script>`              |
| Path Traversal      | `/../../../etc/passwd` / `%2e%2e`        |
| Command Injection   | `; cat /etc/shadow`                       |
| Brute Force Login   | 3 Loginversuche pro IP in 30 Sekunden    |

---

## Erweiterung: Risk-Scoring

Zusätzlich zur reinen Angriffserkennung bewertet das Projekt jede IP-Adresse
mit einem Risiko-Score:

- Jeder Angriffstyp hat ein Gewicht, z.B. `command_injection` und
  `login_bruteforce` zählen stärker als XSS.
- Viele Requests derselben IP können einen kleinen Zusatzpunkt-Bonus geben.
- Aus dem Score wird eine Risikostufe berechnet:
  `INFO`, `LOW`, `MEDIUM`, `HIGH` oder `CRITICAL`.

Das Dashboard zeigt Score und Risikostufe in der Top-IP-Tabelle. Der
`log_analyzer.py` gibt zusätzlich einen Abschnitt `Risk-Scoring nach IP` aus.

---

## Log-Format

Jeder Request wird als JSON-Zeile in `honeypot.log` geschrieben:
Die Angriffspayloads werden erkannt und protokolliert, aber nicht ausgeführt.

```json
{
  "timestamp": "2025-06-08T10:23:45Z",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/api/customers?id=1+OR+1%3D1--",
  "user_agent": "python-attacker-sim/1.0",
  "body_snippet": null,
  "attack_types": ["sql_injection"]
}
```

---

## Konfiguration

Optional können folgende Umgebungsvariablen gesetzt werden:

- `HONEYPOT_HOST` – Host, standardmäßig `127.0.0.1`
- `HONEYPOT_PORT` – Port, standardmäßig `8080`
- `HONEYPOT_LOG_FILE` – Pfad zur Logdatei

---

## Sicherheitshinweis

Dieses Projekt ist **ausschließlich für Lern- und Testzwecke** gedacht.

- Nur auf `127.0.0.1` (localhost) betreiben
- Isolierte VM oder Docker-Netzwerk verwenden
- Niemals auf einem öffentlich erreichbaren Server ohne Netzwerk-Segmentierung
- Keine echten Produktionsdaten in der Nähe

---

## Quellen

- [Viresh Garg — Honeypot and Honeynet as a Service](https://medium.com/@viresh.garg/honeypot-and-honeynet-as-a-service-a-comprehensive-cybersecurity-strategy-dc01eab24848) (Medium, 2024)
- OWASP — Testing for SQL Injection (WSTG-INPV-05)
- Python Docs — `http.server` Standard Library

# 🍯 Honeypot & Honeynet as a Service

> Lernprojekt für Softwarearchitektur — FH Sem. 4  
> Simuliert eine verwundbare Webanwendung, loggt Angreifer-Verhalten und analysiert Angriffsmuster.

---

## ⚡ Quickstart

```bash
# 1. Honeypot starten
python honeypot.py

# 2. Angriffe simulieren (neues Terminal)
python attacker_sim.py

# 3. Logs auswerten
python log_analyzer.py
```

Dann im Browser öffnen: `http://127.0.0.1:8080/stats`

---

## 📁 Projektstruktur

```
honeypot/
├── honeypot.py        # Honeypot-Server (HTTP, Port 8080)
├── attacker_sim.py    # Angriffs-Simulator für Tests
├── log_analyzer.py    # Log-Auswertung & Threat Report
├── honeypot.log       # Wird automatisch erstellt (JSON-Lines)
└── README.md          # Diese Datei
```

---

## 🔧 Voraussetzungen

- Python 3.10+ (keine externen Packages nötig — nur Stdlib)
- Windows / macOS / Linux

---

## 🌐 Endpunkte

| Methode | Pfad             | Beschreibung                        |
|---------|------------------|-------------------------------------|
| GET     | `/`              | App-Info (Fake-Server-Version)      |
| GET     | `/api/customers` | Fake-Kundendaten (JSON)             |
| GET     | `/api/admin`     | Fake-Admin-Credentials (Köder)      |
| GET     | `/api/config`    | Fake-Konfiguration mit DB-Keys      |
| GET     | `/admin`         | Fake-Adminbereich                   |
| POST    | `/admin/login`   | Simulierter Login (immer 401)       |
| GET     | `/stats`         | **Echtzeit-Statistiken des Honeypots** |

---

## 🚨 Erkannte Angriffs-Typen

| Typ                 | Beispiel-Payload                          |
|---------------------|-------------------------------------------|
| SQL Injection        | `?id=1 OR 1=1--` / `UNION SELECT *`      |
| XSS                 | `<script>alert(1)</script>`              |
| Path Traversal      | `/../../../etc/passwd` / `%2e%2e`        |
| Command Injection   | `; cat /etc/shadow`                       |
| Brute Force Login   | Wiederholte POST-Requests auf `/login`   |

---

## 📊 Log-Format

Jeder Request wird als JSON-Zeile in `honeypot.log` geschrieben:

```json
{
  "timestamp": "2025-06-08T10:23:45Z",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/api/customers?id=1 OR 1=1--",
  "user_agent": "python-attacker-sim/1.0",
  "body_snippet": null,
  "attack_types": ["sql_injection"]
}
```

---

## ⚠️ Sicherheitshinweis

Dieses Projekt ist **ausschließlich für Lern- und Testzwecke** gedacht.

- ✅ Nur auf `127.0.0.1` (localhost) betreiben
- ✅ Isolierte VM oder Docker-Netzwerk verwenden
- ❌ Niemals auf einem öffentlich erreichbaren Server ohne Netzwerk-Segmentierung
- ❌ Keine echten Produktionsdaten in der Nähe

---

## 📖 Quellen

- Viresh Garg — *Honeypot and Honeynet as a Service* (Medium, 2024)
- OWASP — Testing for SQL Injection (WSTG-INPV-05)
- Python Docs — `http.server` Standard Library

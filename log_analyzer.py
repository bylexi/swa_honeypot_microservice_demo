"""
Log-Analyzer — Wertet honeypot.log aus
=======================================
Liest die JSON-Logs und erstellt einen strukturierten Threat-Report.
"""

import json
import sys
from collections import Counter, defaultdict

from threat_scoring import build_ip_risk_profiles


def analyze(logfile="honeypot.log"):
    entries = []
    try:
        with open(logfile) as f:
            for line in f:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        print(f"[FEHLER] Log-Datei '{logfile}' nicht gefunden.")
        print("   Starte zuerst honeypot.py und attacker_sim.py.")
        return

    if not entries:
        print("Keine Log-Einträge gefunden.")
        return

    # Aggregation
    ips            = Counter(e["ip"] for e in entries)
    paths          = Counter(e["path"] for e in entries)
    methods        = Counter(e["method"] for e in entries)
    attack_types   = Counter()
    attacks_by_ip  = defaultdict(list)

    for e in entries:
        for a in e.get("attack_types", []):
            attack_types[a] += 1
            attacks_by_ip[e["ip"]].append(a)

    # Report
    sep = "─" * 55
    print(f"\n{'═'*55}")
    print(f"  HONEYPOT THREAT REPORT")
    print(f"  Analysiert: {len(entries)} Log-Einträge")
    print(f"{'═'*55}\n")

    print(f"Überblick")
    print(sep)
    print(f"  Unique IPs:          {len(ips)}")
    print(f"  Gesamt-Requests:     {len(entries)}")
    attack_count = sum(1 for e in entries if e.get("attack_types"))
    print(f"  Erkannte Angriffe:   {attack_count}  ({100*attack_count//len(entries)}%)")
    print(f"  HTTP-Methoden:       {dict(methods)}\n")

    print(f"Angriffs-Typen")
    print(sep)
    if attack_types:
        for atype, count in attack_types.most_common():
            bar = "█" * min(count * 3, 30)
            print(f"  {atype:<22} {bar} {count}")
    else:
        print("  Keine Angriffe erkannt.")
    print()

    print(f"Top-IPs nach Requests")
    print(sep)
    for ip, count in ips.most_common(5):
        atk_count = len(attacks_by_ip[ip])
        flag = "[ANGRIFF]" if atk_count > 0 else "         "
        print(f"  {flag} {ip:<18} {count} Requests, {atk_count} Angriffe")
    print()

    print(f"Risk-Scoring nach IP")
    print(sep)
    for profile in build_ip_risk_profiles(entries, limit=5):
        types = ", ".join(profile["attack_types"].keys()) or "keine"
        print(
            f"  {profile['level']:<8} {profile['ip']:<18} "
            f"Score {profile['score']:>2}  "
            f"{profile['requests']} Requests, {profile['attacks']} Angriffe"
        )
        print(f"           Typen: {types}")
    print()

    print(f"Meist angefragte Pfade")
    print(sep)
    for path, count in paths.most_common(8):
        print(f"  {count:>4}×  {path}")
    print()

    print(f"Letzte 5 Angriffs-Einträge")
    print(sep)
    recent_attacks = [e for e in entries if e.get("attack_types")][-5:]
    for e in recent_attacks:
        ts = e["timestamp"][:19].replace("T", " ")
        atypes = ", ".join(e["attack_types"])
        print(f"  {ts}  {e['ip']}")
        print(f"           {e['method']} {e['path'][:60]}")
        print(f"           Typ: {atypes}\n")

    print(f"{'═'*55}\n")


if __name__ == "__main__":
    logfile = sys.argv[1] if len(sys.argv) > 1 else "honeypot.log"
    analyze(logfile)

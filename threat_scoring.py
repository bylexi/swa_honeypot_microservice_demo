"""
Threat-Scoring für Honeypot-Logs.

Bewertet IP-Adressen nach Angriffstypen und Request-Volumen.
"""

from collections import Counter


ATTACK_WEIGHTS = {
    "sql_injection": 4,
    "path_traversal": 4,
    "command_injection": 5,
    "login_bruteforce": 5,
    "xss": 3,
}


def classify_risk(score: int) -> str:
    """Mappt einen Zahlen-Score auf eine leicht lesbare Risikostufe."""
    if score >= 20:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def request_volume_bonus(request_count: int) -> int:
    """Gibt Zusatzpunkte für ungewöhnlich viele Requests derselben IP."""
    if request_count >= 30:
        return 5
    if request_count >= 15:
        return 3
    if request_count >= 8:
        return 1
    return 0


def score_ip_entries(entries: list[dict]) -> dict:
    """Berechnet Score, Level und Details für eine einzelne IP."""
    attack_counter: Counter = Counter()
    for entry in entries:
        for attack_type in entry.get("attack_types", []):
            attack_counter[attack_type] += 1

    attack_score = sum(
        ATTACK_WEIGHTS.get(attack_type, 1) * count
        for attack_type, count in attack_counter.items()
    )
    bonus = request_volume_bonus(len(entries))
    score = attack_score + bonus

    return {
        "score": score,
        "level": classify_risk(score),
        "requests": len(entries),
        "attacks": sum(attack_counter.values()),
        "attack_types": dict(attack_counter.most_common()),
        "volume_bonus": bonus,
    }


def build_ip_risk_profiles(entries: list[dict], limit: int | None = None) -> list[dict]:
    """Gruppiert Log-Einträge nach IP und sortiert sie nach Risiko."""
    entries_by_ip: dict[str, list[dict]] = {}
    for entry in entries:
        ip = entry.get("ip", "?")
        entries_by_ip.setdefault(ip, []).append(entry)

    profiles = []
    for ip, ip_entries in entries_by_ip.items():
        profile = score_ip_entries(ip_entries)
        profile["ip"] = ip
        profiles.append(profile)

    profiles.sort(key=lambda item: (item["score"], item["requests"]), reverse=True)
    return profiles[:limit] if limit else profiles

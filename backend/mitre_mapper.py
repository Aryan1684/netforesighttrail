MITRE_MAP = {
    "Benign": {"tactic": "Normal", "technique_id": None, "technique": "No attack technique mapped"},
    "FTP-BruteForce": {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
    "SSH-Bruteforce": {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
}


def map_label(label: str) -> dict:
    return dict(
        MITRE_MAP.get(
            label,
            {
                "tactic": "Unmapped",
                "technique_id": None,
                "technique": "No direct mapping available",
            },
        )
    )


def path_priority(current_label: str, next_label: str, current_conf: float, next_conf: float, risk_score: int) -> dict:
    evidence = (
        0.55 * current_conf
        + 0.30 * min(1.0, risk_score / 100.0)
        + 0.15 * next_conf
    )
    level = "HIGH" if evidence >= 0.70 else ("MEDIUM" if evidence >= 0.45 else "LOW")
    return {
        "level": level,
        "score": round(evidence * 100, 2),
        "current_label": current_label,
        "next_label": next_label,
    }

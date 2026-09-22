MITRE_MAP = {
    "Normal": {
        "tactic": "Normal",
        "technique_id": None,
        "technique": "No attack technique mapped",
    },
    "Analysis": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique": "Active Scanning",
    },
    "Reconnaissance": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique": "Active Scanning",
    },
    "DoS": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
    },
    "Exploits": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
    },
    "Worms": {
        "tactic": "Lateral Movement",
        "technique_id": "T1210",
        "technique": "Exploitation of Remote Services",
    },
    "Backdoor": {
        "tactic": "Unmapped",
        "technique_id": None,
        "technique": "No direct category-level mapping",
    },
    "Fuzzers": {
        "tactic": "Unmapped",
        "technique_id": None,
        "technique": "No direct category-level mapping",
    },
    "Generic": {
        "tactic": "Unmapped",
        "technique_id": None,
        "technique": "No direct category-level mapping",
    },
    "Shellcode": {
        "tactic": "Unmapped",
        "technique_id": None,
        "technique": "No direct category-level mapping",
    },
}


def map_label(label: str) -> dict:
    return dict(MITRE_MAP.get(label, {
        "tactic": "Unmapped",
        "technique_id": None,
        "technique": "No direct category-level mapping",
    }))


def priority(current_conf: float, next_conf: float, risk_score: int) -> dict:
    evidence = 0.55 * current_conf + 0.30 * (risk_score / 100.0) + 0.15 * next_conf
    level = "HIGH" if evidence >= 0.70 else ("MEDIUM" if evidence >= 0.45 else "LOW")
    return {"level": level, "score": round(evidence * 100, 2)}

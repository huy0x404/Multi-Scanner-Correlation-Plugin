from __future__ import annotations

ANALYSIS_MODES: dict[str, dict[str, str]] = {
    "auto": {
        "label": "Auto",
        "description": "Use all provided sources.",
        "behavior": "Parses all scanner files and correlates full evidence.",
    },
    "1": {
        "label": "Top 1 Source",
        "description": "Analyze only the most informative source.",
        "behavior": "Chooses by parsed finding count, not scanner name priority.",
    },
    "2": {
        "label": "Top 2 Sources",
        "description": "Analyze two most informative sources.",
        "behavior": "Chooses by parsed finding count, then correlates overlap.",
    },
    "3": {
        "label": "Top 3 Sources",
        "description": "Analyze three most informative sources.",
        "behavior": "Chooses by parsed finding count, then correlates overlap.",
    },
    "4": {
        "label": "Top 4 Sources",
        "description": "Analyze four most informative sources.",
        "behavior": "Equivalent to all sources when four inputs are provided.",
    },
}

RISK_MODE_META: dict[str, dict[str, str]] = {
    "realistic": {
        "label": "Realistic (default)",
        "description": "Balanced for real operations with mixed scanner signals.",
        "best_for": "Daily monitoring and production-like triage.",
    },
    "capability": {
        "label": "Capability",
        "description": "Emphasizes scanner strengths (OpenVAS/Nikto/Wireshark signals).",
        "best_for": "Security assessment with stronger vulnerability confidence.",
    },
    "balanced": {
        "label": "Balanced (legacy)",
        "description": "Backward-compatible profile from previous releases.",
        "best_for": "Consistency with historical reports.",
    },
    "dos": {
        "label": "DoS Focus",
        "description": "Prioritizes traffic anomalies and DoS indicators.",
        "best_for": "Load attack and traffic-abuse investigations.",
    },
}

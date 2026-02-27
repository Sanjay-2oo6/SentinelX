from datetime import datetime

from execution.event_log_and_alert_service import latest_alert_banner, latest_check_payload


def _parse_date(value: str):
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.min


def build_dashboard_payload(email: str) -> dict:
    payload = latest_check_payload(email)
    if not payload:
        return {
            "email": email,
            "breach_count": 0,
            "risk_score": 0,
            "risk_category": "Low",
            "most_recent_breach": None,
            "breaches": [],
            "recommendations": [],
            "show_alert_banner": False,
        }

    breaches = payload.get("breaches", [])
    recent = None
    if breaches:
        recent = sorted(breaches, key=lambda item: _parse_date(item.get("breach_date", "")), reverse=True)[0]

    return {
        "email": payload.get("email", email),
        "breach_count": payload.get("breach_count", 0),
        "risk_score": payload.get("risk_score", 0),
        "risk_category": payload.get("risk_category", "Low"),
        "most_recent_breach": recent,
        "breaches": breaches,
        "recommendations": payload.get("recommendations", []),
        "show_alert_banner": latest_alert_banner(payload.get("email", email)),
    }

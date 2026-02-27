from datetime import datetime


LOW_MAX = 30
MEDIUM_MAX = 70


def _data_type_weight(data_type: str) -> int:
    value = data_type.lower()
    if "financial" in value or "credit" in value or "bank" in value:
        return 35
    if "password" in value:
        return 25
    if value == "email":
        return 5
    return 10


def _recency_weight(breach_date: str) -> int:
    try:
        breach_year = datetime.fromisoformat(breach_date).year
    except Exception:
        return 0
    current_year = datetime.utcnow().year
    age = max(current_year - breach_year, 0)
    if age <= 1:
        return 20
    if age <= 3:
        return 10
    if age <= 5:
        return 5
    return 0


def _risk_category(score: int) -> str:
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def _recommendations_from_data_types(data_types: set[str]) -> list[str]:
    recommendations = []
    if "password" in data_types or "passwords" in data_types:
        recommendations.append("Reset password immediately and enable 2FA.")
    if "financial info" in data_types or any("financial" in item for item in data_types):
        recommendations.append("Monitor bank statements and card activity.")
    if data_types == {"email"}:
        recommendations.append("Beware of phishing attempts and suspicious emails.")
    if "username" in data_types and (
        "password" in data_types or "passwords" in data_types
    ):
        recommendations.append("Change passwords across platforms and avoid reuse.")

    if not recommendations:
        recommendations.append("Review account security settings and enable 2FA where possible.")

    return recommendations


def evaluate_risk_and_recommendations(check_payload: dict) -> dict:
    breaches = check_payload.get("breaches", [])
    breach_count = len(breaches)

    score = min(breach_count * 10, 30)
    all_data_types: set[str] = set()

    for breach in breaches:
        data_exposed = breach.get("data_exposed", [])
        for item in data_exposed:
            normalized = item.lower()
            all_data_types.add(normalized)
            score += _data_type_weight(item)
        score += _recency_weight(breach.get("breach_date", ""))

    score = min(score, 100)
    category = _risk_category(score)
    recommendations = _recommendations_from_data_types(all_data_types)

    output = dict(check_payload)
    output["risk_score"] = score
    output["risk_category"] = category
    output["recommendations"] = recommendations
    return output

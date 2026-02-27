from execution.breach_check_service import run_breach_check
from execution.event_log_and_alert_service import get_monitored_emails, process_check_result
from execution.risk_response_service import evaluate_risk_and_recommendations


def run_monitoring_cycle() -> dict:
    emails = get_monitored_emails()
    processed = 0
    alerts = 0

    for email in emails:
        check_payload = run_breach_check(email)
        enriched = evaluate_risk_and_recommendations(check_payload)
        outcome = process_check_result(enriched)
        processed += 1
        if outcome.get("alert_triggered"):
            alerts += 1

    return {
        "processed_emails": processed,
        "alerts_triggered": alerts,
    }

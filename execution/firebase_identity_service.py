import json
import logging
import os
from datetime import datetime, timezone

import firebase_admin
from firebase_admin import auth, credentials, firestore

from execution.breach_check_service import validate_email

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _initialize_firebase_app() -> firebase_admin.App:
    try:
        app = firebase_admin.get_app()
        logger.info(f"[FIREBASE] Using existing app, project: {app.project_id}")
        return app
    except ValueError:
        service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH", "").strip()
        service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
        project_id = os.getenv("FIREBASE_PROJECT_ID", "").strip() or None

        logger.info(f"[FIREBASE] Initializing app, service_account_path={service_account_path}")
        
        cred = None
        if service_account_path:
            cred = credentials.Certificate(service_account_path)
        elif service_account_json:
            cred = credentials.Certificate(json.loads(service_account_json))
        else:
            google_app_credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
            if google_app_credentials:
                cred = credentials.Certificate(google_app_credentials)

        if cred is None:
            raise RuntimeError(
                "Firebase Admin is not configured. Set FIREBASE_SERVICE_ACCOUNT_PATH or FIREBASE_SERVICE_ACCOUNT_JSON"
            )

        options = {"projectId": project_id} if project_id else None
        app = firebase_admin.initialize_app(cred, options)
        logger.info(f"[FIREBASE] App initialized, project: {app.project_id}")
        return app


def _firestore_client() -> firestore.Client:
    app = _initialize_firebase_app()
    return firestore.client(app=app)


def _user_doc_ref(uid: str):
    if not uid:
        raise ValueError("Missing uid")
    return _firestore_client().collection("users").document(uid)


def verify_bearer_token(authorization_header: str) -> dict:
    if not authorization_header:
        raise ValueError("Missing Authorization header")

    parts = authorization_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise ValueError("Authorization header must be in format: Bearer <token>")

    token = parts[1].strip()
    logger.info(f"[TOKEN] Token length: {len(token)}")
    logger.info(f"[TOKEN] Token prefix: {token[:50]}...")
    
    _initialize_firebase_app()
    
    try:
        # Allow up to 10 seconds of clock skew between local machine and Google servers
        decoded = auth.verify_id_token(token, clock_skew_seconds=10)
        logger.info(f"[TOKEN] Verified! aud={decoded.get('aud')}, iss={decoded.get('iss')}")
        logger.info(f"[TOKEN] uid={decoded.get('uid')}, email={decoded.get('email')}")
        return decoded
    except Exception as e:
        logger.error(f"[TOKEN] Verification FAILED: {type(e).__name__}: {e}")
        raise


def upsert_user_profile(uid: str, email: str, display_name: str | None) -> dict:
    normalized_email = validate_email(email)
    doc_ref = _user_doc_ref(uid)
    existing = doc_ref.get()
    if not existing.exists:
        payload = {
            "email": normalized_email,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "monitoredEmails": [],
        }
        doc_ref.set(payload)
        return {
            "uid": uid,
            "email": normalized_email,
            "monitoredEmails": [],
        }

    current = existing.to_dict() or {}
    return {
        "uid": uid,
        "email": current.get("email", normalized_email),
        "monitoredEmails": current.get("monitoredEmails", []),
    }


def get_user_profile(uid: str) -> dict | None:
    snapshot = _user_doc_ref(uid).get()
    if not snapshot.exists:
        return None
    payload = snapshot.to_dict() or {}
    return {
        "uid": uid,
        "email": payload.get("email", ""),
        "monitoredEmails": payload.get("monitoredEmails", []),
    }


def list_monitored_emails(uid: str) -> list[dict]:
    profile = get_user_profile(uid) or {}
    return list(profile.get("monitoredEmails", []))


def add_monitored_email(uid: str, email: str) -> dict:
    normalized_email = validate_email(email)
    doc_ref = _user_doc_ref(uid)
    snapshot = doc_ref.get()
    if not snapshot.exists:
        raise RuntimeError("User profile not found")

    payload = snapshot.to_dict() or {}
    current = list(payload.get("monitoredEmails", []))
    if normalized_email in current:
        raise ValueError("Email already monitored")

    updated = current + [normalized_email]
    doc_ref.update({"monitoredEmails": updated})
    return updated


def remove_monitored_email(uid: str, email: str) -> None:
    normalized_email = validate_email(email)
    doc_ref = _user_doc_ref(uid)
    snapshot = doc_ref.get()
    if not snapshot.exists:
        raise RuntimeError("User profile not found")

    payload = snapshot.to_dict() or {}
    current = list(payload.get("monitoredEmails", []))
    if normalized_email not in current:
        raise LookupError("Email not found")

    updated = [item for item in current if item != normalized_email]
    
    # Also remove any alerts associated with this email
    alerts = list(payload.get("alerts", []))
    updated_alerts = [alert for alert in alerts if alert.get("email") != normalized_email]
    
    doc_ref.update({
        "monitoredEmails": updated,
        "alerts": updated_alerts
    })
    return updated


# ============ Alert Functions ============

def get_all_users() -> list[dict]:
    """Get all users from Firestore for scheduled scanning."""
    db = _firestore_client()
    users = []
    try:
        docs = db.collection("users").stream()
        for doc in docs:
            data = doc.to_dict() or {}
            users.append({
                "uid": doc.id,
                "email": data.get("email", ""),
                "monitoredEmails": data.get("monitoredEmails", []),
            })
    except Exception:
        pass
    return users


def get_user_alerts(uid: str) -> list[dict]:
    """Get all alerts for a user."""
    doc_ref = _user_doc_ref(uid)
    snapshot = doc_ref.get()
    if not snapshot.exists:
        return []
    payload = snapshot.to_dict() or {}
    return list(payload.get("alerts", []))


def alert_exists(uid: str, monitored_email: str, breach_name: str) -> bool:
    """Check if an alert already exists for this breach."""
    alerts = get_user_alerts(uid)
    for alert in alerts:
        if alert.get("email") == monitored_email:
            existing_breaches = alert.get("breaches", [])
            for breach in existing_breaches:
                # Handle both string and dict formats
                name = breach if isinstance(breach, str) else breach.get("name", "")
                if name == breach_name:
                    return True
    return False


def add_alert(uid: str, monitored_email: str, breach_result: dict) -> dict:
    """
    Add a new breach alert for a user.
    Only adds breaches that don't already have alerts.
    
    Args:
        uid: User's Firebase UID
        monitored_email: The email that was breached
        breach_result: Result from hibp_service.check_email()
    
    Returns:
        The alert object that was added, or None if no new breaches
    """
    if not breach_result.get("breached"):
        return None
    
    breaches = breach_result.get("breaches", [])
    if not breaches:
        return None
    
    # Filter out breaches that already have alerts
    # Handle both string and dict formats for breach names
    new_breaches = []
    for breach in breaches:
        breach_name = breach if isinstance(breach, str) else breach.get("name", "")
        if breach_name and not alert_exists(uid, monitored_email, breach_name):
            new_breaches.append(breach_name if isinstance(breach, str) else breach)
    
    if not new_breaches:
        return None
    
    doc_ref = _user_doc_ref(uid)
    snapshot = doc_ref.get()
    if not snapshot.exists:
        return None
    
    # Create alert object including riskScore
    alert = {
        "email": monitored_email,
        "breachCount": len(new_breaches),
        "breaches": new_breaches,
        "severity": breach_result.get("severity", "Unknown"),
        "riskScore": breach_result.get("riskScore", 0),
        "detectedAt": _utc_now(),
    }
    
    # Get existing alerts and append
    payload = snapshot.to_dict() or {}
    alerts = list(payload.get("alerts", []))
    
    # Check if there's an existing alert for this email and merge
    existing_alert_idx = None
    for i, a in enumerate(alerts):
        if a.get("email") == monitored_email:
            existing_alert_idx = i
            break
    
    if existing_alert_idx is not None:
        # Merge new breaches into existing alert
        existing = alerts[existing_alert_idx]
        existing_breaches = existing.get("breaches", [])
        merged_breaches = existing_breaches + new_breaches
        # Recalculate riskScore for merged breaches
        merged_risk_score = min(len(merged_breaches) * 25, 100)
        alerts[existing_alert_idx] = {
            "email": monitored_email,
            "breachCount": len(merged_breaches),
            "breaches": merged_breaches,
            "severity": breach_result.get("severity", existing.get("severity", "Unknown")),
            "riskScore": merged_risk_score,
            "detectedAt": _utc_now(),
        }
        alert = alerts[existing_alert_idx]
    else:
        alerts.append(alert)
    
    doc_ref.update({"alerts": alerts})
    return alert

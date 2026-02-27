import logging
import os
import threading
import time
from functools import wraps

from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

# Configure logging to BOTH console and file
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('debug.log', mode='w'),
    ]
)
logger = logging.getLogger(__name__)

from execution.breach_check_service import run_breach_check
from execution.dashboard_view_service import build_dashboard_payload
from execution.event_log_and_alert_service import init_db, process_check_result
from execution.firebase_identity_service import (
    add_monitored_email,
    get_user_profile,
    get_user_alerts,
    list_monitored_emails,
    remove_monitored_email,
    upsert_user_profile,
    verify_bearer_token,
)
from execution.risk_response_service import evaluate_risk_and_recommendations
from execution.scan_scheduler_service import start_scheduler, check_single_email_with_alert


def _start_scheduler_thread() -> None:
    """Start the Phase 3 breach scan scheduler."""
    monitor_enabled = os.getenv("MONITOR_ENABLED", "true").strip().lower() == "true"
    if not monitor_enabled:
        return
    try:
        start_scheduler()
    except Exception:
        pass


def create_app() -> Flask:
    load_dotenv()
    init_db()

    # Configure static folder path
    project_root = Path(__file__).resolve().parents[1]
    static_folder = project_root / "static"

    app = Flask(__name__, static_folder=str(static_folder), static_url_path="/static")

    @app.after_request
    def set_coop_headers(response):
        # Allow Firebase Auth popup to communicate back to the main window
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
        return response

    @app.before_request
    def log_request():
        logger.info(f"[REQUEST] {request.method} {request.path}")

    # Test endpoint
    @app.get("/test")
    def test_endpoint():
        logger.info("[TEST] Test endpoint called")
        return jsonify({"status": "ok"}), 200

    # Serve frontend at root
    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    def _auth_error(message: str, code: int = 401):
        return jsonify({"error": message}), code

    def _firebase_error(message: str):
        return jsonify({"error": message}), 500

    def require_auth(handler):
        @wraps(handler)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            logger.info(f"[AUTH] Request to {request.path}, auth header present: {bool(auth_header)}")
            try:
                decoded = verify_bearer_token(auth_header)
                logger.info(f"[AUTH] Token verified for uid: {decoded.get('uid')}")
            except ValueError as exc:
                logger.error(f"[AUTH] ValueError: {exc}")
                return _auth_error(str(exc), 401)
            except Exception as exc:
                logger.error(f"[AUTH] Token verification failed: {type(exc).__name__}: {exc}")
                return _auth_error(f"Token error: {str(exc)}", 401)

            uid = decoded.get("uid", "")
            email = decoded.get("email", "")
            display_name = decoded.get("name", "")

            if not uid or not email:
                return _auth_error("Token must include uid and email", 401)

            try:
                profile = upsert_user_profile(uid, email, display_name)
            except RuntimeError as exc:
                return _firebase_error(str(exc))
            except Exception:
                return _firebase_error("Unable to load user profile")

            request.user = {
                "uid": uid,
                "email": email,
                "display_name": display_name,
                "profile": profile,
            }
            return handler(*args, **kwargs)

        return wrapper

    @app.post("/check-email")
    def check_email():
        payload = request.get_json(silent=True) or {}
        email = payload.get("email", "")

        try:
            check_result = run_breach_check(email)
            scored = evaluate_risk_and_recommendations(check_result)
            event_result = process_check_result(scored)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            return jsonify({"error": "Unable to process breach check"}), 500

        response = {
            "email": scored["email"],
            "breach_count": scored["breach_count"],
            "risk_score": scored["risk_score"],
            "risk_category": scored["risk_category"],
            "breaches": scored["breaches"],
            "recommendations": scored["recommendations"],
            "alert_triggered": event_result.get("alert_triggered", False),
            "new_breach_count": event_result.get("new_breach_count", 0),
        }
        return jsonify(response), 200

    @app.get("/dashboard")
    def dashboard():
        email = request.args.get("email", "").strip().lower()
        if not email:
            return jsonify({"error": "Email query parameter is required"}), 400

        try:
            result = build_dashboard_payload(email)
        except Exception:
            return jsonify({"error": "Unable to build dashboard"}), 500
        return jsonify(result), 200

    @app.get("/auth/me")
    @require_auth
    def auth_me():
        return (
            jsonify(
                {
                    "uid": request.user["uid"],
                    "email": request.user["email"],
                    "display_name": request.user["display_name"],
                    "profile": request.user["profile"],
                }
            ),
            200,
        )

    @app.get("/user/profile")
    @require_auth
    def user_profile():
        try:
            profile = get_user_profile(request.user["uid"]) or request.user["profile"]
            return (
                jsonify(
                    {
                        "uid": request.user["uid"],
                        "email": profile.get("email", request.user["email"]),
                        "monitoredEmails": profile.get("monitoredEmails", []),
                    }
                ),
                200,
            )
        except RuntimeError as exc:
            return _firebase_error(str(exc))
        except Exception:
            return jsonify({"error": "Unable to fetch profile"}), 500

    @app.get("/user/emails")
    @require_auth
    def user_emails_list():
        try:
            emails = list_monitored_emails(request.user["uid"])
            return jsonify(emails), 200
        except RuntimeError as exc:
            return _firebase_error(str(exc))
        except Exception:
            return jsonify({"error": "Unable to list monitored emails"}), 500

    @app.post("/user/emails")
    @require_auth
    def user_emails_add():
        payload = request.get_json(silent=True) or {}
        email = payload.get("email", "")
        try:
            updated = add_monitored_email(request.user["uid"], email)
            
            # Phase 3: Immediate breach check on add
            breach_result = None
            try:
                breach_result = check_single_email_with_alert(
                    request.user["uid"],
                    request.user["email"],
                    email.strip().lower()
                )
            except Exception:
                pass  # Don't fail the add if check fails
            
            response = {
                "emails": updated,
                "breach_check": breach_result,
            }
            return jsonify(response), 200
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return _firebase_error(str(exc))
        except Exception:
            return jsonify({"error": "Unable to add monitored email"}), 500

    @app.get("/user/alerts")
    @require_auth
    def user_alerts_list():
        """Get all breach alerts for the current user."""
        try:
            alerts = get_user_alerts(request.user["uid"])
            return jsonify(alerts), 200
        except RuntimeError as exc:
            return _firebase_error(str(exc))
        except Exception:
            return jsonify({"error": "Unable to fetch alerts"}), 500

    @app.delete("/user/emails")
    @require_auth
    def user_emails_delete():
        payload = request.get_json(silent=True) or {}
        email = payload.get("email", "")
        if not email:
            return jsonify({"error": "Email is required"}), 400

        try:
            updated = remove_monitored_email(request.user["uid"], email)
            return jsonify(updated), 200
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except RuntimeError as exc:
            return _firebase_error(str(exc))
        except Exception:
            return jsonify({"error": "Unable to remove monitored email"}), 500

    _start_scheduler_thread()
    return app


app = create_app()

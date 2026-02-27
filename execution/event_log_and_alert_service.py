import json
import os
import smtplib
import sqlite3
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path


def _db_path() -> str:
    configured = os.getenv("DB_PATH", "data/breach_monitor.db")
    path = Path(configured)
    if not path.is_absolute():
        root = Path(__file__).resolve().parents[1]
        path = root / configured
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    conn = sqlite3.connect(_db_path())
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                breach_count INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                new_breach_count INTEGER NOT NULL,
                breaches_json TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS monitored_emails (
                email TEXT PRIMARY KEY,
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _fetch_latest_payload(email: str) -> dict | None:
    conn = sqlite3.connect(_db_path())
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM checks WHERE email = ? ORDER BY id DESC LIMIT 1", (email,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return json.loads(row[0])
    finally:
        conn.close()


def _send_email_alert(email: str, new_breaches: list[dict]) -> bool:
    from_addr = os.getenv("ALERT_EMAIL_FROM", "").strip()
    to_addr = os.getenv("ALERT_EMAIL_TO", "").strip()
    smtp_host = os.getenv("SMTP_HOST", "").strip()

    if not (from_addr and to_addr and smtp_host):
        return False

    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()

    message = EmailMessage()
    message["Subject"] = f"🚨 SentinelX Security Alert: Data Breach for {email}"
    message["From"] = from_addr
    message["To"] = to_addr

    names = ", ".join(item.get("name", "Unknown") for item in new_breaches)
    
    # Text fallback
    message.set_content(f"SentinelX Security Alert\n\nNew breaches detected for {email}:\n{names}\n\nPlease sign in to your dashboard at SentinelX to see full details and remediation steps.")

    # High-visibility HTML Template
    breaches_html = ""
    for b in new_breaches:
        if isinstance(b, str):
            name = b
            date = "2021-03-20"  # Historical fallback
            data = "Email Addresses, Passwords"
        else:
            name = b.get("name", "Unknown")
            date = b.get("breach_date", "2021-03-20")
            data = ", ".join(b.get("data_exposed", [])) or "Email Addresses, Passwords"
            
        breaches_html += f"""
        <tr style="border-bottom: 1px solid #444;">
            <td style="padding: 15px; color: #ffffff !important; font-weight: bold; font-size: 14px;">{name}</td>
            <td style="padding: 15px; color: #ffffff !important; font-size: 13px;">{date}</td>
            <td style="padding: 15px; color: #ffffff !important; font-family: 'Courier New', monospace; font-size: 13px; font-weight: bold;">{data}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ margin: 0; padding: 0; background-color: #000000; color: #ffffff; }}
        </style>
    </head>
    <body style="background-color: #000000; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #0d1117; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #1f6feb 0%, #238636 100%); padding: 30px; text-align: center;">
                <h1 style="margin: 0; color: #ffffff; font-size: 32px; font-weight: 800; letter-spacing: 2px;">SENTINELX</h1>
                <p style="margin: 5px 0 0 0; color: #ffffff; opacity: 0.9; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Security Alert System</p>
            </div>
            
            <!-- Body -->
            <div style="padding: 40px;">
                <div style="background-color: #da3633; color: #ffffff !important; padding: 12px 20px; border-radius: 6px; display: inline-block; font-weight: bold; margin-bottom: 25px;">
                    🚨 <span style="color: #ffffff !important;">CRITICAL SECURITY WARNING</span>
                </div>
                
                <p style="font-size: 17px; line-height: 1.6; color: #ffffff !important; margin-bottom: 20px;">
                    Hello,
                </p>
                
                <p style="font-size: 18px; line-height: 1.6; color: #ffffff !important; margin-bottom: 20px;">
                    Our monitoring system has detected your credentials in <strong><span style="color: #ffffff !important;">{len(new_breaches)}</span></strong> new security breach{'es' if len(new_breaches) > 1 else ''}.
                </p>
                
                <div style="background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 25px 0;">
                    <p style="margin: 0; font-size: 15px; color: #ffffff !important;">Target Account:</p>
                    <p style="margin: 5px 0 0 0; font-size: 18px; color: #ffffff !important; font-weight: bold;">{email}</p>
                </div>
                
                <h3 style="color: #ffffff !important; font-size: 18px; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 35px;">Breach Details</h3>
                <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                    <thead>
                        <tr style="text-align: left; background-color: #161b22;">
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Source</th>
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Breached Date</th>
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Compromised Data Categories</th>
                        </tr>
                    </thead>
                    <tbody>
                        {breaches_html}
                    </tbody>
                </table>
                
                <div style="margin: 40px 0; padding: 25px; background-color: #2386361a; border-left: 4px solid #238636; border-radius: 0 8px 8px 0;">
                    <h4 style="margin: 0 0 10px 0; color: #ffffff !important; font-size: 18px;">🛡️ <span style="color: #ffffff !important;">Remediation plan:</span></h4>
                    <ul style="margin: 0; padding-left: 20px; color: #ffffff !important; font-size: 15px; line-height: 1.8;">
                        <li style="color: #ffffff !important;">Change your password immediately for all affected services.</li>
                        <li style="color: #ffffff !important;">Enable Multi-Factor Authentication (MFA) where available.</li>
                        <li style="color: #ffffff !important;">Monitor your financial accounts for unauthorized activity.</li>
                        <li style="color: #ffffff !important;">Be cautious of phishing emails attempting to exploit this breach</li>
                        <li style="color: #ffffff !important;">Consider using a password manager with unique passwords</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 40px;">
                    <a href="http://127.0.0.1:5000" style="background-color: #238636; color: #ffffff !important; padding: 18px 35px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block;">Secure My Dashboard</a>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #010409; padding: 25px; text-align: center; border-top: 1px solid #30363d;">
                <p style="margin: 0; font-size: 12px; color: #ffffff !important;">&copy; 2026 SentinelX Terminal. All rights reserved.</p>
                <p style="margin: 8px 0 0 0; font-size: 11px; color: #ffffff !important;">This is an automated security notification. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """
    message.add_alternative(html_content, subtype="html")

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.send_message(message)
        return True
    except Exception:
        return False


def process_check_result(payload: dict) -> dict:
    init_db()
    email = payload.get("email", "")
    previous_payload = _fetch_latest_payload(email)

    previous_names = set()
    if previous_payload:
        previous_names = {item.get("name", "") for item in previous_payload.get("breaches", [])}

    current_breaches = payload.get("breaches", [])
    new_breaches = [item for item in current_breaches if item.get("name", "") not in previous_names]

    conn = sqlite3.connect(_db_path())
    alert_triggered = False
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO checks (email, checked_at, breach_count, risk_score, risk_category, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                _utc_now(),
                payload.get("breach_count", 0),
                payload.get("risk_score", 0),
                payload.get("risk_category", "Low"),
                json.dumps(payload),
            ),
        )

        cursor.execute(
            """
            INSERT INTO monitored_emails (email, active, created_at)
            VALUES (?, 1, ?)
            ON CONFLICT(email) DO UPDATE SET active = 1
            """,
            (email, _utc_now()),
        )

        if previous_payload is not None and new_breaches:
            alert_triggered = _send_email_alert(email, new_breaches)
            cursor.execute(
                """
                INSERT INTO alerts (email, created_at, new_breach_count, breaches_json, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    email,
                    _utc_now(),
                    len(new_breaches),
                    json.dumps(new_breaches),
                    "sent" if alert_triggered else "logged",
                ),
            )

        conn.commit()
    finally:
        conn.close()

    return {
        "new_breach_count": len(new_breaches) if previous_payload is not None else 0,
        "new_breaches": new_breaches if previous_payload is not None else [],
        "alert_triggered": alert_triggered,
    }


def latest_alert_banner(email: str) -> bool:
    init_db()
    conn = sqlite3.connect(_db_path())
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM alerts WHERE email = ? ORDER BY id DESC LIMIT 1", (email,)
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()


def get_monitored_emails() -> list[str]:
    init_db()
    conn = sqlite3.connect(_db_path())
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM monitored_emails WHERE active = 1 ORDER BY email")
        return [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()


def latest_check_payload(email: str) -> dict | None:
    init_db()
    return _fetch_latest_payload(email)

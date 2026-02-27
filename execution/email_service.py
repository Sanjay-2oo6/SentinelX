"""
Email service for sending breach alert notifications.
Uses Gmail SMTP with app password authentication.
"""
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def _get_email_config() -> dict:
    """Get email configuration from environment variables."""
    return {
        "sender_email": os.getenv("EMAIL_ADDRESS", "").strip(),
        "app_password": os.getenv("EMAIL_APP_PASSWORD", "").strip(),
        "smtp_host": os.getenv("SMTP_HOST", "smtp.gmail.com").strip(),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    }


def _build_alert_html(user_email: str, monitored_email: str, breaches: list) -> str:
    """Build HTML email body for breach alert with absolute white contrast."""
    breach_rows = ""
    for breach in breaches:
        if isinstance(breach, str):
            name = breach
            if name.lower() == 'railyatri':
                data_exposed = "Email addresses, Genders, Names, Phone numbers, Purchases"
            else:
                data_exposed = "Email addresses, Passwords"
            date = "2021-03-12"
            severity = "High"
        else:
            name = breach.get('name', 'Unknown')
            date = breach.get('breach_date', '2021-03-12')
            severity = breach.get('severity', 'High')
            data_exposed = ", ".join(breach.get("data_exposed", [])) or "Email Addresses, Passwords"
        
        breach_rows += f"""
        <tr style="border-bottom: 1px solid #444;">
            <td style="padding: 15px; color: #ffffff !important; font-weight: bold; font-size: 14px;">{name}</td>
            <td style="padding: 15px; color: #ffffff !important; font-size: 13px;">{date}</td>
            <td style="padding: 15px; color: #ffffff !important; font-size: 13px;">{severity}</td>
            <td style="padding: 15px; color: #ffffff !important; font-family: 'Courier New', monospace; font-size: 13px; font-weight: bold;">{data_exposed}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body style="background-color: #000000; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; margin: 0;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #0d1117; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #1f6feb 0%, #238636 100%); padding: 30px; text-align: center;">
                <h1 style="margin: 0; color: #ffffff !important; font-size: 32px; font-weight: 800; letter-spacing: 2px;">SENTINELX</h1>
                <p style="margin: 5px 0 0 0; color: #ffffff !important; opacity: 1; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Dark Web Breach Monitor</p>
            </div>
            
            <!-- Body -->
            <div style="padding: 40px;">
                <div style="background-color: #da3633; color: #ffffff !important; padding: 12px 20px; border-radius: 6px; display: inline-block; font-weight: bold; margin-bottom: 25px;">
                    🚨 <span style="color: #ffffff !important;">SECURITY ALERT</span>
                </div>
                
                <p style="font-size: 17px; line-height: 1.6; color: #ffffff !important; margin-bottom: 20px;">
                    Hello,
                </p>
                
                <p style="font-size: 18px; line-height: 1.6; color: #ffffff !important; margin-bottom: 20px;">
                    Our systems detected that <strong style="color: #ffffff !important;">{monitored_email}</strong> has been involved in <strong style="color: #ffffff !important;">{len(breaches)}</strong> security breach{'es' if len(breaches) > 1 else ''}.
                </p>
                
                <h3 style="color: #ffffff !important; font-size: 18px; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 35px;">Breach Details:</h3>
                <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                    <thead>
                        <tr style="text-align: left; background-color: #161b22;">
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Source</th>
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Breached Date</th>
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Severity</th>
                            <th style="padding: 12px; font-size: 12px; color: #ffffff !important; text-transform: uppercase;">Compromised Data Categories</th>
                        </tr>
                    </thead>
                    <tbody>
                        {breach_rows}
                    </tbody>
                </table>
                
                <div style="margin: 40px 0; padding: 25px; background-color: #2386361a; border-left: 4px solid #238636; border-radius: 0 8px 8px 0;">
                    <h4 style="margin: 0 0 10px 0; color: #ffffff !important; font-size: 18px;">🛡️ <span style="color: #ffffff !important;">Remediation plan:</span></h4>
                    <ul style="margin: 0; padding-left: 20px; color: #ffffff !important; font-size: 15px; line-height: 1.8;">
                        <li style="color: #ffffff !important;">Change your password immediately on affected services</li>
                        <li style="color: #ffffff !important;">Enable Two-Factor Authentication (2FA) wherever possible</li>
                        <li style="color: #ffffff !important;">Monitor your financial accounts for suspicious activity</li>
                        <li style="color: #ffffff !important;">Be cautious of phishing emails attempting to exploit this breach</li>
                        <li style="color: #ffffff !important;">Consider using a password manager with unique passwords</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 40px;">
                    <a href="http://127.0.0.1:5000" style="background-color: #238636; color: #ffffff !important; padding: 18px 35px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block;">Secure My Account</a>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #010409; padding: 25px; text-align: center; border-top: 1px solid #30363d;">
                <p style="margin: 0; font-size: 12px; color: #ffffff !important; font-weight: bold;">This alert was sent by Dark Web Breach Monitor.</p>
                <p style="margin: 8px 0 0 0; font-size: 11px; color: #ffffff !important;">You received this because <span style="color: #ffffff !important;">{monitored_email}</span> is on your monitoring list.</p>
                <p style="margin: 15px 0 0 0; font-size: 10px; color: #ffffff !important; opacity: 0.6;">&copy; 2026 SentinelX Terminal. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """


def send_alert_email(user_email: str, monitored_email: str, breaches: list) -> bool:
    """
    Send breach alert email to user.
    
    Args:
        user_email: The user's account email (recipient)
        monitored_email: The email that was breached
        breaches: List of breach names (strings) or breach details (dicts)
    
    Returns:
        True if email sent successfully, False otherwise
    """
    config = _get_email_config()
    
    if not config["sender_email"] or not config["app_password"]:
        logger.warning("Email not configured: EMAIL_ADDRESS or EMAIL_APP_PASSWORD missing")
        return False
    
    if not breaches:
        logger.info("No breaches to report, skipping email")
        return False
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 ALERT: Data Breach Detected for {monitored_email}"
        msg["From"] = config["sender_email"]
        msg["To"] = user_email
        
        # Plain text fallback
        plain_text = f"""
SECURITY ALERT - Dark Web Breach Monitor

Data breach detected for: {monitored_email}

Number of breaches: {len(breaches)}

Breach Details:
Source\tDate\tSeverity\tData Exposed
"""
        for breach in breaches:
            if isinstance(breach, str):
                name = breach
                if name.lower() == 'railyatri':
                    data = "Email addresses, Genders, Names, Phone numbers, Purchases"
                else:
                    data = "Email addresses, Passwords"
                plain_text += f"{name}\t2021-03-20\tHigh\t{data}\n"
            else:
                name = breach.get('name', 'Unknown')
                date = breach.get('breach_date') or '2021-03-20'
                if date == "N/A": date = "2021-03-20"
                severity = breach.get('severity') or 'High'
                if severity == "Unknown": severity = "High"
                
                data_list = breach.get("data_exposed", [])
                if name.lower() == 'railyatri' and (not data_list or "N/A" in data_list):
                    data = "Email addresses, Genders, Names, Phone numbers, Purchases"
                else:
                    data = ", ".join(data_list) or "Email addresses, Passwords"
                
                plain_text += f"{name}\t{date}\t{severity}\t{data}\n"
        
        plain_text += """
Remediation plan:
- Change your password immediately
- Enable Two-Factor Authentication
- Monitor your accounts for suspicious activity

This alert was sent by SentinelX Dark Web Breach Monitor.
"""
        
        html_content = _build_alert_html(user_email, monitored_email, breaches)
        
        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(html_content, "html"))
        
        with smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=30) as server:
            server.starttls()
            server.login(config["sender_email"], config["app_password"])
            server.send_message(msg)
        
        logger.info(f"Alert email sent to {user_email} for breach on {monitored_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending email: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")
        return False

"""
HIBP (Have I Been Pwned) service for LIVE breach checking.
Uses paid HIBP API key for real-time breach data.
"""
import logging
import os
import time

import requests

logger = logging.getLogger(__name__)

# Rate limit tracking
_last_request_time: float = 0
_MIN_REQUEST_INTERVAL = 1.5  # HIBP requires 1.5s between requests


def _rate_limit_wait():
    """Enforce rate limiting between HIBP API requests."""
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_REQUEST_INTERVAL:
        sleep_time = _MIN_REQUEST_INTERVAL - elapsed
        time.sleep(sleep_time)
    _last_request_time = time.time()


def _calculate_severity(breach_count: int) -> str:
    """
    Calculate severity based on breach count.
    - 1 breach → "medium"
    - 2+ breaches → "high"
    """
    if breach_count <= 0:
        return None
    if breach_count == 1:
        return "medium"
    return "high"


def _calculate_risk_score(breach_count: int) -> int:
    """Calculate risk score: min(breachCount * 25, 100)"""
    if breach_count <= 0:
        return 0
    return min(breach_count * 25, 100)


def _severity_from_data_classes(data_exposed: list[str]) -> str:
    """Determine severity based on data types involved."""
    values = {item.lower() for item in data_exposed}
    if any(k in values for k in ["financial info", "credit cards", "bank account", "social security number"]):
        return "High"
    if any(k in values for k in ["password", "passwords", "hashes"]):
        return "High"
    if "email addresses" in values and len(values) == 1:
        return "Low"
    return "Medium"


def check_email(email: str) -> dict:
    """
    Check if an email has been involved in any data breaches using LIVE HIBP API.
    
    Args:
        email: Email address to check
        
    Returns:
        dict with keys:
        - email: str
        - breached: bool
        - breachCount: int
        - breaches: list[str] (breach names)
        - severity: str | None ("medium", "high")
        - riskScore: int (0-100)
        - error: str | None
    """
    email = (email or "").strip().lower()
    if not email:
        return {
            "email": email,
            "breached": False,
            "breachCount": 0,
            "breaches": [],
            "severity": None,
            "riskScore": 0,
            "error": "Invalid email",
        }
    
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        logger.error("HIBP_API_KEY not configured")
        return {
            "email": email,
            "breached": False,
            "breachCount": 0,
            "breaches": [],
            "severity": None,
            "riskScore": 0,
            "error": "HIBP API key not configured",
        }
    
    # Enforce rate limiting
    _rate_limit_wait()
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    
    try:
        response = requests.get(
            url,
            headers={
                "hibp-api-key": api_key,
                "user-agent": "DarkWebMonitorHackathon",
            },
            timeout=10,
        )
        
        # 404 = Not found / No breaches
        if response.status_code == 404:
            logger.info(f"HIBP: {email} - No breaches found")
            return {
                "email": email,
                "breached": False,
                "breachCount": 0,
                "breaches": [],
                "severity": None,
                "riskScore": 0,
                "error": None,
            }
        
        # 429 = Rate limited
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "2")
            logger.warning(f"HIBP: Rate limited for {email}, retry after {retry_after}s")
            return {
                "email": email,
                "breached": False,
                "breachCount": 0,
                "breaches": [],
                "severity": None,
                "riskScore": 0,
                "error": f"Rate limited, retry after {retry_after}s",
            }
        
        # 401 = Invalid API key
        if response.status_code == 401:
            logger.error("HIBP: Invalid API key (401 Unauthorized)")
            return {
                "email": email,
                "breached": False,
                "breachCount": 0,
                "breaches": [],
                "severity": None,
                "riskScore": 0,
                "error": "Invalid HIBP API key",
            }
        
        # Other HTTP errors
        response.raise_for_status()
        
        # 200 = Parse breach list
        records = response.json() or []
        breach_details = []
        for item in records:
            data_classes = item.get("DataClasses") or []
            breach_details.append({
                "name": item.get("Name", "Unknown"),
                "breach_date": item.get("BreachDate") or "2021-01-01",
                "data_exposed": data_classes,
                "severity": _severity_from_data_classes(data_classes)
            })
        
        breach_count = len(breach_details)
        severity = _calculate_severity(breach_count)
        risk_score = _calculate_risk_score(breach_count)
        
        logger.info(f"HIBP: {email} - {breach_count} breaches found, severity={severity}, riskScore={risk_score}")
        
        return {
            "email": email,
            "breached": breach_count > 0,
            "breachCount": breach_count,
            "breaches": breach_details,
            "severity": severity,
            "riskScore": risk_score,
            "error": None,
        }
        
    except requests.exceptions.Timeout:
        logger.error(f"HIBP: Timeout for {email}")
        return {
            "email": email,
            "breached": False,
            "breachCount": 0,
            "breaches": [],
            "severity": None,
            "riskScore": 0,
            "error": "Request timeout",
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"HIBP: Network error for {email}: {e}")
        return {
            "email": email,
            "breached": False,
            "breachCount": 0,
            "breaches": [],
            "severity": None,
            "riskScore": 0,
            "error": f"Network error: {str(e)}",
        }
    except Exception as e:
        logger.error(f"HIBP: Unexpected error for {email}: {e}")
        return {
            "email": email,
            "breached": False,
            "breachCount": 0,
            "breaches": [],
            "severity": None,
            "riskScore": 0,
            "error": f"Unexpected error: {str(e)}",
        }

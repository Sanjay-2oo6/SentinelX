"""
Scheduled breach scanning service.
Runs periodic scans across all monitored emails for all users.
"""
import logging
import os
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_scan_interval_hours() -> float:
    """Get scan interval from environment, default 3 hours."""
    try:
        return float(os.getenv("SCAN_INTERVAL_HOURS", "3"))
    except ValueError:
        return 3.0


def run_full_scan() -> dict:
    """
    Run a full breach scan across all users and their monitored emails.
    
    Returns:
        dict with scan statistics
    """
    # Import here to avoid circular imports
    from execution.firebase_identity_service import get_all_users, add_alert, get_user_profile
    from execution.hibp_service import check_email
    from execution.email_service import send_alert_email
    
    start_time = datetime.now(timezone.utc)
    logger.info(f"[SCAN] Starting full breach scan at {start_time.isoformat()}")
    
    stats = {
        "started_at": start_time.isoformat(),
        "users_scanned": 0,
        "emails_checked": 0,
        "breaches_found": 0,
        "alerts_created": 0,
        "emails_sent": 0,
        "errors": 0,
    }
    
    try:
        users = get_all_users()
        logger.info(f"[SCAN] Found {len(users)} users to scan")
        
        for user in users:
            uid = user.get("uid")
            user_email = user.get("email", "")
            monitored_emails = user.get("monitoredEmails", [])
            
            if not uid or not monitored_emails:
                continue
            
            stats["users_scanned"] += 1
            logger.info(f"[SCAN] Scanning user {uid[:8]}... ({len(monitored_emails)} emails)")
            
            for monitored_email in monitored_emails:
                try:
                    stats["emails_checked"] += 1
                    
                    # Check for breaches
                    result = check_email(monitored_email)
                    
                    if result.get("error"):
                        logger.warning(f"[SCAN] Error checking {monitored_email}: {result['error']}")
                        stats["errors"] += 1
                        continue
                    
                    if not result.get("breached"):
                        continue
                    
                    stats["breaches_found"] += result.get("breachCount", 0)
                    
                    # Add alert if new breaches found
                    alert = add_alert(uid, monitored_email, result)
                    
                    if alert:
                        stats["alerts_created"] += 1
                        logger.info(f"[SCAN] New alert created for {monitored_email}: {alert.get('breachCount')} breaches, severity={alert.get('severity')}, riskScore={alert.get('riskScore')}")
                        
                        # Send email notification
                        if user_email:
                            try:
                                sent = send_alert_email(
                                    user_email,
                                    monitored_email,
                                    alert.get("breaches", [])
                                )
                                if sent:
                                    stats["emails_sent"] += 1
                            except Exception as e:
                                logger.error(f"[SCAN] Failed to send email: {e}")
                    
                except Exception as e:
                    logger.error(f"[SCAN] Error processing {monitored_email}: {e}")
                    stats["errors"] += 1
                    continue
        
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()
        stats["completed_at"] = end_time.isoformat()
        stats["duration_seconds"] = duration
        
        logger.info(f"[SCAN] Completed in {duration:.1f}s - "
                   f"{stats['users_scanned']} users, "
                   f"{stats['emails_checked']} emails, "
                   f"{stats['breaches_found']} breaches, "
                   f"{stats['alerts_created']} new alerts, "
                   f"{stats['emails_sent']} emails sent")
        
    except Exception as e:
        logger.error(f"[SCAN] Fatal error during scan: {e}")
        stats["fatal_error"] = str(e)
    
    return stats


def check_single_email_with_alert(uid: str, user_email: str, monitored_email: str) -> dict:
    """
    Check a single email for breaches and create alert if found.
    Used for immediate check when adding a new monitored email.
    
    Args:
        uid: User's Firebase UID
        user_email: User's account email (for notifications)
        monitored_email: The email to check for breaches
    
    Returns:
        The breach check result with alert status
    """
    from execution.hibp_service import check_email
    from execution.firebase_identity_service import add_alert
    from execution.email_service import send_alert_email
    
    logger.info(f"[CHECK] Immediate breach check for {monitored_email}")
    
    result = check_email(monitored_email)
    result["alert_created"] = False
    result["email_sent"] = False
    
    if result.get("error"):
        logger.warning(f"[CHECK] Error checking {monitored_email}: {result['error']}")
        return result
    
    if not result.get("breached"):
        logger.info(f"[CHECK] No breaches found for {monitored_email}")
        return result
    
    # Try to create alert
    try:
        alert = add_alert(uid, monitored_email, result)
        if alert:
            result["alert_created"] = True
            logger.info(f"[CHECK] Alert created for {monitored_email}")
            
            # Send notification email
            if user_email:
                try:
                    sent = send_alert_email(
                        user_email,
                        monitored_email,
                        alert.get("breaches", [])
                    )
                    result["email_sent"] = sent
                except Exception as e:
                    logger.error(f"[CHECK] Failed to send email: {e}")
    except Exception as e:
        logger.error(f"[CHECK] Failed to create alert: {e}")
    
    return result


_scheduler_thread: threading.Thread | None = None
_scheduler_running = False


def start_scheduler():
    """Start the background scheduler for periodic breach scans."""
    global _scheduler_thread, _scheduler_running
    
    if _scheduler_running:
        logger.info("[SCHEDULER] Already running")
        return
    
    _scheduler_running = True
    
    def scheduler_worker():
        global _scheduler_running
        
        interval_hours = get_scan_interval_hours()
        interval_seconds = interval_hours * 3600
        
        logger.info(f"[SCHEDULER] Started with {interval_hours}h interval")
        
        # Run initial scan on startup
        logger.info("[SCHEDULER] Running startup scan...")
        try:
            run_full_scan()
        except Exception as e:
            logger.error(f"[SCHEDULER] Startup scan failed: {e}")
        
        # Then loop forever with interval
        while _scheduler_running:
            logger.info(f"[SCHEDULER] Sleeping for {interval_hours} hours...")
            
            # Sleep in chunks so we can stop gracefully
            sleep_chunks = int(interval_seconds / 30)
            for _ in range(sleep_chunks):
                if not _scheduler_running:
                    break
                time.sleep(30)
            
            if not _scheduler_running:
                break
            
            # Run scheduled scan
            logger.info("[SCHEDULER] Running scheduled scan...")
            try:
                run_full_scan()
            except Exception as e:
                logger.error(f"[SCHEDULER] Scheduled scan failed: {e}")
        
        logger.info("[SCHEDULER] Stopped")
    
    _scheduler_thread = threading.Thread(target=scheduler_worker, daemon=True, name="BreachScanner")
    _scheduler_thread.start()
    logger.info("[SCHEDULER] Background thread started")


def stop_scheduler():
    """Stop the background scheduler."""
    global _scheduler_running
    _scheduler_running = False
    logger.info("[SCHEDULER] Stop requested")

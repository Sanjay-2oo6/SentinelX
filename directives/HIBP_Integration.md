# HIBP API Integration Documentation

## Overview
SentinelX integrates with the **Have I Been Pwned (HIBP)** API to monitor user credentials against known data breaches. This integration ensures that users receive immediate alerts when their private information is leaked on the dark web.

## Architecture
The integration is handled by the `execution/hibp_service.py` and `execution/breach_check_service.py` modules.

### Key Components

1.  **Request Handler**: Uses the `requests` library to query the HIBP `v3` API.
2.  **Authentication**: Securely authenticates using the `hibp-api-key` header, sourced from environment variables.
3.  **Data Transformation**: Normalizes raw HIBP JSON responses into a clean format used by the SentinelX dashboard.
4.  **Severity Engine**: Calculates risk levels (Low, Medium, High) based on the `DataClasses` (e.g., Passwords, IP Addresses) returned by HIBP.

## API Usage
- **Endpoint**: `https://haveibeenpwned.com/api/v3/breachedaccount/{email}`
- **Method**: `GET`
- **Parameters**: `truncateResponse=false` (to get full breach details)
- **Headers**:
    - `hibp-api-key`: `[REDACTED]`
    - `user-agent`: `SentinelX-Breach-Monitor`

## Error Handling & Rate Limiting
- **429 (Too Many Requests)**: Handled by retry logic or background service throttling.
- **404 (Not Found)**: Interpreted as "No Breaches Documented" for the specific email.
- **Failover**: In the absence of an API key, the system can fall back to a simulation mode for demonstration purposes.

## Deliverable Status
- [x] API Integration logic implemented.
- [x] Secure credential management integrated.
- [x] Risk calculation engine implemented.
- [x] Real-time dashboard display connected.

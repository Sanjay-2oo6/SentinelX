# SOP: Manual Breach Check

## Goal
Return breach status, risk score, and recommendations for a single email check.

## Inputs
- Email address from user input.

## Flow
1. Validate and normalize the email.
2. Run breach source lookup and normalize breach records.
3. Compute risk score and risk category.
4. Generate remediation recommendations.
5. Persist the check result and evaluate whether new breaches were detected.
6. Return structured response for UI/API.

## Expected Output
- Email
- Breach count
- Risk score and category
- Breach list
- Recommendations
- New breach alert status

## Edge Cases
- Invalid email format.
- Breach source unavailable (use fallback data source).
- No breaches found.

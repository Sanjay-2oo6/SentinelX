# SOP: Dashboard Review

## Goal
Provide a consistent dashboard view of the latest breach posture for one email.

## Inputs
- Email query parameter.

## Flow
1. Load latest stored check result for the email.
2. Build dashboard summary fields.
3. Include latest breach details and risk indicator.
4. Include recommendations and alert banner state.

## Expected Output
- Breach count
- Risk score and category
- Most recent breach
- Breach list
- Recommendations
- Alert banner visibility flag

## Edge Cases
- No previous check result.
- Missing email input.

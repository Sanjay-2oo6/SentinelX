# SOP: Periodic Monitoring and Alert

## Goal
Simulate scheduled monitoring and trigger alerts when newly observed breaches appear.

## Inputs
- Active monitored email list.
- Monitoring interval configuration.

## Flow
1. Execute monitoring cycle on schedule.
2. For each monitored email, run the same breach check and scoring flow.
3. Compare current and previous breach states.
4. Log alert event when new breaches are detected.
5. Trigger email alert when configured.
6. Expose alert state for dashboard banner display.

## Expected Output
- Monitoring cycle summary (processed emails, alerts triggered).
- Persistent alert events.
- Dashboard alert banner state.

## Edge Cases
- Empty monitored email list.
- SMTP not configured (log only).
- Source failures during cycle.

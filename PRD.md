📄 Product Requirements Document
Project: Dark Web Breach Monitor – Web Application
1. Product Overview

The Dark Web Breach Monitor is a web-based cybersecurity tool that allows users to check whether their email address has been exposed in known data breaches.

The system integrates with the Have I Been Pwned API (or a simulated breach dataset) to:

Detect exposed accounts

Display breach details

Calculate a risk score

Provide remediation recommendations

Trigger real-time alerts

The goal is to provide a simple, accessible interface for users to understand their digital exposure risk.

2. Objectives

Allow users to check breach status of an email address.

Display structured breach information in a dashboard.

Provide risk scoring based on breach severity.

Offer actionable remediation recommendations.

Demonstrate real-time alert capability.

Maintain clean 3-layer architecture (Directive, Orchestration, Execution).

3. Target Users

Students concerned about cybersecurity

Individuals checking personal email safety

Hackathon judges evaluating architecture

Small organizations testing breach exposure

4. Functional Requirements
4.1 Email Breach Check

User enters email address.

System must:

Validate email format

Call backend API endpoint

Fetch breach details

Return structured JSON response

Response format:

{
  "email": "example@email.com",
  "breach_count": 2,
  "risk_score": 75,
  "breaches": [
    {
      "name": "Adobe",
      "breach_date": "2013-10-04",
      "data_exposed": ["Email", "Password"],
      "severity": "High"
    }
  ]
}
4.2 Dashboard Display

The dashboard must display:

Total breach count

Risk score (0–100)

Most recent breach

Breach list (card layout or table)

Visual indicator (Low / Medium / High Risk)

Optional:

Timeline chart of breaches

Pie chart of exposed data types

4.3 Risk Scoring System

Risk score calculated based on:

Number of breaches

Type of exposed data

Password → High weight

Financial info → Very high weight

Email only → Low weight

Recency of breach

Score range: 0–100

Risk categories:

0–30 → Low

31–70 → Medium

71–100 → High

4.4 Real-Time Alert System

When new breach detected:

Log event to database

Trigger email alert

Show alert banner on dashboard

System should simulate periodic monitoring using scheduled checks.

4.5 Remediation Recommendation Engine

Based on exposed data types:

Data Exposed	Recommendation
Password	Reset password immediately, enable 2FA
Financial Info	Monitor bank statements
Email Only	Beware of phishing attempts
Username + Password	Change passwords across platforms

Recommendations displayed below breach summary.

5. Non-Functional Requirements

Response time under 3 seconds

Modular architecture

Deterministic execution scripts

Secure handling of API keys in .env

Clean UI design (dark cybersecurity theme)

Mobile responsive layout

6. Tech Stack

Frontend:

Streamlit or Flask + HTML/CSS

Chart.js or Plotly for visualization

Backend:

Flask API

Python execution scripts

Database:

SQLite (local)

APIs:

Have I Been Pwned API

Environment:

Visual Studio Code

Git version control

7. System Architecture

Three-layer model:

Layer 1 – Directives
Defines workflows and SOPs.

Layer 2 – Orchestration
Reads directives and routes execution.

Layer 3 – Execution
Handles API calls, database operations, and data processing.

8. UI Requirements

Landing Page:

Title: “Dark Web Breach Monitor”

Email input field

Check button

Minimalistic cyber theme

Results Page:

Risk score indicator

Breach summary cards

Recommendations section

Alert banner if high risk

Color coding:

Green → Low

Yellow → Medium

Red → High

9. Deliverables

Functional web application

Breach monitoring dashboard

Real-time alert demo

API integration documentation

Remediation recommendation system

Clean repository structure

10. Success Metrics

Successful breach check execution

Correct risk scoring

Clean separation of layers

No inline API calls outside execution layer

Working real-time alert demo
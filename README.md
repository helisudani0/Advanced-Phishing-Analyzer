# Advanced SOC‑Grade Phishing Analyzer

An **industry-style phishing email analysis system** designed to simulate **real Security Operations Center (SOC) workflows**.

This project performs **real-time forensic analysis of email (.eml) files**, identifies phishing indicators, assigns an **explainable risk score**, and generates **professional SOC-ready reports** in PDF, JSON, and CSV formats.

Built with a focus on **accuracy, explainability, and low false positives**.

## Key Features

-Real-time `.eml` email analysis
-Explainable phishing detection (reason-based, not black-box)
-Header, sender, domain & URL inspection
-Lookalike & spoofed domain detection
-Risk scoring system (0–100)
-Professional SOC-style PDF reports
-JSON & CSV exports for automation
-Modern GUI for analysts (Tkinter)

This analyzer:
- Explains **what indicators triggered**
- Shows **how risky the email actually is**
- Helps analysts make **informed decisions**
- Reduces unnecessary false positives


## What the Analyzer Checks

### Email Headers

* Sender / Return‑Path mismatch
* SPF / DKIM / DMARC inconsistencies
* Mail server anomalies

### URLs & Domains

* Lookalike domains (typosquatting)
* Suspicious TLDs
* Redirect-based phishing behavior

### Behavioral Indicators

* Urgency language
* Brand impersonation
* Suspicious sender identity



## Author: Heli Sudani

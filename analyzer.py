# analyzer.py
import re
from email import policy
from email.parser import BytesParser
from scoring_engine import explain_risk
from utils import extract_urls, timestamp, log_results
from header_analysis import analyze_headers
from url_analysis import analyze_urls
from attachment_analysis import analyze_attachments


# ---------------- RISK NORMALIZATION ----------------
def normalize_score(header, content, url, attachment):
    """
    Government-grade conservative scoring
    Caps + weighting to prevent score inflation
    """
    header = min(header, 25)
    content = min(content, 30)
    url = min(url, 30)
    attachment = min(attachment, 15)

    total = header + content + url + attachment
    return min(total, 100)


def risk_level(score):
    if score < 30:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    return "HIGH"


# ---------------- CORE ANALYZER ----------------
def analyze_email(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # ---------------- HEADER ANALYSIS ----------------
    headers = analyze_headers(msg)
    header_score = 0

    if headers.get("SPF") == "fail":
        header_score += 8
    if headers.get("DKIM") == "fail":
        header_score += 8
    if headers.get("DMARC") == "fail":
        header_score += 6
    if headers.get("Received hops", 0) > 6:
        header_score += 3

    # ---------------- CONTENT ANALYSIS ----------------
    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""

    content_score = 0
    phishing_phrases = [
        "verify your account",
        "reset your password",
        "unusual activity",
        "confirm immediately",
        "account suspended"
    ]

    for phrase in phishing_phrases:
        if phrase in text.lower():
            content_score += 5

    # Cap conservative
    content_score = min(content_score, 30)

    # ---------------- URL ANALYSIS ----------------
    urls = extract_urls(text)
    url_results = analyze_urls(urls)
    url_score = sum(u["risk"] for u in url_results)
    url_score = min(url_score, 30)

    # ---------------- ATTACHMENT ANALYSIS ----------------
    attachment_results = analyze_attachments(msg)
    attachment_score = sum(a["risk"] for a in attachment_results)
    attachment_score = min(attachment_score, 15)

    # ---------------- FINAL SCORE ----------------
    total_score = normalize_score(
        header_score,
        content_score,
        url_score,
        attachment_score
    )

    level = risk_level(total_score)
    if level == "LOW":
        threat_label = "No confirmed threat detected"
    elif level == "MEDIUM":
        threat_label = "Potentially suspicious email"
    else:
        threat_label = "Confirmed phishing threat"

    explanation = explain_risk(
    header_score,
    content_score,
    url_score,
    attachment_score
)



    analysis = {
    "file": file_path,
    "timestamp": timestamp(),
    "score": total_score,
    "level": level,
    "threat": "Phishing / Suspicious Content",

    "from": msg.get("From", "Unknown"),
    "return_path": msg.get("Return-Path", "Not provided"),
    "subject": msg.get("Subject", "No subject"),

    "headers": headers,
    "urls": url_results,
    "attachments": attachment_results,

    "header_score": header_score,
    "content_score": content_score,
    "url_score": url_score,
    "attachment_score": attachment_score,

    "breakdown": {
        "header": header_score,
        "content": content_score,
        "url": url_score,
        "attachment": attachment_score
    },
        

    "explanation": explanation
}


    log_results(analysis)
    return analysis

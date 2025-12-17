import os
import json
import csv
import re
from urllib.parse import urlparse
import datetime

# ---------------- CONFIG ----------------
CSV_LOG = "logs.csv"
JSON_LOG = "logs.json"
PDF_DIR = "reports"
os.makedirs(PDF_DIR, exist_ok=True)

URL_SHORTENERS = ["bit.ly", "t.co", "tinyurl.com"]
RISKY_EXTENSIONS = [".exe", ".js", ".vbs", ".zip", ".html"]
SUSPICIOUS_KEYWORDS = {
    "urgent": 10, "verify": 10, "password": 20,
    "invoice": 20, "payment": 20, "immediately": 10
}

# ---------------- HELPERS ----------------
def extract_domain(addr):
    m = re.search(r'@([\w\.-]+)', addr)
    return m.group(1).lower() if m else ""

def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)

def risk_level(score):
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

def log_results(data):
    # CSV
    exists = os.path.isfile(CSV_LOG)
    with open(CSV_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not exists:
            writer.writeheader()
        writer.writerow(data)

    # JSON
    logs = []
    if os.path.exists(JSON_LOG):
        with open(JSON_LOG, "r", encoding="utf-8") as jf:
            logs = json.load(jf)
    logs.append(data)
    with open(JSON_LOG, "w", encoding="utf-8") as jf:
        json.dump(logs, jf, indent=2)

def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

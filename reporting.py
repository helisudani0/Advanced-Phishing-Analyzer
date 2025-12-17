import json
import csv
from fpdf import FPDF
import os

# ---------------- HUMAN-FRIENDLY SUMMARY ----------------
def generate_summary(analysis):
    """
    Returns a simple summary for non-technical users.
    """
    level = analysis.get("level", "LOW")
    if level == "LOW":
        return "This email appears safe. No phishing or malicious indicators were detected."
    elif level == "MEDIUM":
        return "This email shows some suspicious characteristics. Exercise caution and avoid clicking unknown links."
    else:
        return "This email is likely malicious. Do NOT click links or open attachments."

def explain_section(title, score, max_score, explanation):
    """
    Friendly explanation for each section.
    """
    if score == 0:
        return f"{title}: No issues detected. This area appears safe.\n"
    return (
        f"{title}: Some concerns identified.\n"
        f"Impact level: {score}/{max_score}\n"
        f"{explanation}\n"
    )

# ---------------- PDF EXPORT ----------------
def export_pdf(analysis, output_path):
    """
    Generates a readable PDF report.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Email Security Analysis Report", ln=True)
    pdf.ln(5)

    # Overview
    pdf.set_font("Helvetica", size=12)
    pdf.multi_cell(0, 8, f"""
File Analyzed : {analysis['file']}
Sender        : {analysis.get('from', 'N/A')}
Subject       : {analysis.get('subject', 'N/A')}
Analysis Time : {analysis['timestamp']}

RISK LEVEL    : {analysis['level']}
SCORE         : {analysis['score']}/100

SUMMARY:
{generate_summary(analysis)}
""")
    pdf.ln(3)

    # Header analysis
    pdf.multi_cell(
        0,
        8,
        explain_section(
            "Sender Authentication",
            analysis["breakdown"].get("header", 0),
            25,
            "SPF, DKIM, and DMARC checks were evaluated."
        ),
    )

    # Content analysis
    pdf.multi_cell(
        0,
        8,
        explain_section(
            "Email Content",
            analysis["breakdown"].get("content", 0),
            30,
            "Checked for suspicious words or phishing patterns."
        ),
    )

    # URL analysis
    if analysis.get("urls"):
        pdf.multi_cell(
            0,
            8,
            explain_section(
                "Links",
                analysis["breakdown"].get("url", 0),
                25,
                "Links in the email were evaluated for potential risks."
            ),
        )
    else:
        pdf.multi_cell(0, 8, "Links: No suspicious links detected.\n")

    # Attachments
    if analysis.get("attachments"):
        pdf.multi_cell(
            0,
            8,
            explain_section(
                "Attachments",
                analysis["breakdown"].get("attachment", 0),
                20,
                "Attachments were checked for malicious content."
            ),
        )
        for att in analysis["attachments"]:
            fname = att.get("filename", "Unknown")
            risk = att.get("risk", 0)
            expl = att.get("explanation", "No issues detected") if risk == 0 else att.get("explanation")
            pdf.multi_cell(0, 6, f"- {fname}: Risk={risk}, Explanation={expl}")
    else:
        pdf.multi_cell(0, 8, "Attachments: No attachments found.\n")

    # Recommendations
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Recommended Action", ln=True)
    pdf.set_font("Helvetica", size=12)

    if analysis["level"] == "LOW":
        pdf.multi_cell(0, 8, "- No action required.")
    elif analysis["level"] == "MEDIUM":
        pdf.multi_cell(
            0,
            8,
            "- Avoid clicking unknown links\n- Verify the sender if unsure"
        )
    else:
        pdf.multi_cell(
            0,
            8,
            "- Do NOT click links\n- Do NOT open attachments\n- Report to your security team"
        )

    pdf.output(output_path)
    return output_path

# ---------------- CSV + JSON EXPORT ----------------
def export_csv_json(analysis, base_path):
    """
    Saves machine-readable CSV and JSON reports.
    Returns the file paths.
    """
    json_path = f"{base_path}.json"
    csv_path = f"{base_path}.csv"

    # JSON
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(analysis, jf, indent=4)

    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["Field", "Value"])
        writer.writerow(["File", analysis["file"]])
        writer.writerow(["Sender", analysis.get("from", "N/A")])
        writer.writerow(["Subject", analysis.get("subject", "N/A")])
        writer.writerow(["Timestamp", analysis["timestamp"]])
        writer.writerow(["Risk Level", analysis["level"]])
        writer.writerow(["Score", analysis["score"]])
        writer.writerow([])
        writer.writerow(["Score Breakdown"])
        for k, v in analysis.get("breakdown", {}).items():
            writer.writerow([k, v])

    return csv_path, json_path

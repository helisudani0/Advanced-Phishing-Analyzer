from utils import risk_level

# ---------------- SCORING ----------------
def calculate_risk_score(header_score, content_score, url_score, attachment_score):
    total_score = header_score + content_score + url_score + attachment_score
    return min(total_score, 100)

def explain_risk(header_score, content_score, url_score, attachment_score):
    explanation = f"""
TOTAL SCORE BREAKDOWN:
- Header Analysis     : {header_score}/25
- Content Analysis    : {content_score}/30
- URL Analysis        : {url_score}/25
- Attachment Analysis : {attachment_score}/20
"""
    level = risk_level(header_score + content_score + url_score + attachment_score)
    return level, explanation

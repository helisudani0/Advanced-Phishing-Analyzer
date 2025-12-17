from utils import URL_SHORTENERS

def analyze_urls(urls):
    results = []
    for u in urls:
        domain = u.split("/")[2] if "/" in u else u
        risk = 0
        explanation = ""
        if domain in URL_SHORTENERS:
            risk += 15
            explanation = "URL shortener detected"
        if any(c.isdigit() for c in domain.replace(".", "")):
            risk += 20
            explanation = "IP-based URL detected"
        if not explanation:
            explanation = "URL checked, no high-risk patterns detected"
        results.append({"url": u, "risk": risk, "explanation": explanation})
    return results

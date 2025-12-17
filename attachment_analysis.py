from utils import RISKY_EXTENSIONS

def analyze_attachments(msg):
    attachments = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            ext = "." + fn.split(".")[-1].lower()
            risk = 0
            explanation = ""
            if ext in RISKY_EXTENSIONS:
                risk += 30
                explanation = f"High-risk extension: {ext}"
            if "." in fn[:-len(ext)]:
                risk += 10
                explanation += " + double extension"
            if not explanation:
                explanation = "Attachment OK"
            attachments.append({"filename": fn, "risk": risk, "explanation": explanation})
    return attachments

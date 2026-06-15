import os
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise ValueError("Missing GROQ_API_KEY in .env file")

llm = ChatGroq(api_key=GROQ_API_KEY, model_name="llama-3.3-70b-versatile")


def generate_report(email_text, iocs, vt_results, urlscan_results, abuseipdb_results):

    prompt = f"""

    You are an expert cybersecurity analyst specializing in phishing detection.
    Analyze the following email and investigation results.

    ORIGINAL EMAIL:
    {email_text}

    EXTRACTED IOCs:
    {iocs}

    VIRUSTOTAL RESULTS:
    {vt_results}

    URLSCAN RESULTS:
    {urlscan_results}

    ABUSEIPDB RESULTS:
    {abuseipdb_results}

        Perform TWO analyses:

    1. TECHNICAL ANALYSIS — based on the API results above
    2. AI PHISHING DETECTION — analyze the email text itself for:
       - Urgency or fear inducing language
       - Impersonation attempts
       - Unusual requests (credentials, payments, personal info)
       - Too good to be true offers
       - Subtle grammar patterns typical of AI generated text
       - Mismatched sender identity

    Differentiate spam from phishing:
    - Classify as Spam if the email is unsolicited promotional or bulk content without credential theft, impersonation, payment fraud, malware delivery, or sensitive data collection.
    - Classify as Phishing if the email attempts to steal credentials, personal information, payments, MFA codes, or impersonates a trusted entity to force user action.
    - Classify as Suspicious if the evidence is unclear, mixed, or potentially risky but not enough to confirm phishing.
    - Classify as Legitimate if the email has no malicious, suspicious, or unsolicited bulk indicators.


    Return a structured threat report with:
    - VERDICT: Phishing / Spam /Suspicious / Legitimate
    - CONFIDENCE: High / Medium / Low
    - TECHNICAL FINDINGS: summary of API results
    - AI PHISHING INDICATORS: what behavioral signals were detected
    - RECOMMENDED ACTION: Block / Quarantine / Safe
    - EXPLANATION: clear summary for a non technical user
    """

    response = llm.invoke(prompt)

    return response.content

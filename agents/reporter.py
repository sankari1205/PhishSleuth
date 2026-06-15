import os
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

llm = ChatGroq(api_key=os.getenv("GROQ_API_KEY"), model_name="llama-3.3-70b-versatile")


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

    Return a structured threat report with:
    - VERDICT: Phishing / Suspicious / Legitimate
    - CONFIDENCE: High / Medium / Low
    - TECHNICAL FINDINGS: summary of API results
    - AI PHISHING INDICATORS: what behavioral signals were detected
    - RECOMMENDED ACTION: Block / Quarantine / Safe
    - EXPLANATION: clear summary for a non technical user
    """

    response = llm.invoke(prompt)

    return response.content

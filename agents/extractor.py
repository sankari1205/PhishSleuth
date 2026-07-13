import os
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise ValueError("Missing GROQ_API_KEY in .env file")

llm = ChatGroq(api_key=GROQ_API_KEY, model_name="llama-3.3-70b-versatile")


def extract_iocs(email_text):

    prompt = f"""

    You are a cybersecurity analyst. Analyze this raw email and extract all indicators of compromise (IOCs).
    
    Email:
    {email_text}
    
    Extract and return ONLY a JSON object with these fields:
    {{
        "urls": ["list of all URLs found"],
        "ips": ["list of all IP addresses found"],
        "domains": ["list of all domains found"],
        "sender_email": "sender email address",
        "reply_to": "reply-to address if different from sender",
        "subject": "email subject"
    }}
    
    Return ONLY the JSON. No explanation. No markdown.
    """

    response = llm.invoke(prompt)

    content = response.content.strip()

    if content.startswith("```"):

        content = content.split("\n", 1)[1]

    if content.endswith("```"):

        content = content.rsplit("```", 1)[0]

    content = content.strip()

    return content

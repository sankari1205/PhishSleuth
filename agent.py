import os
import json
from langchain_groq import ChatGroq
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.prompts import ChatPromptTemplate
from langchain.tools import StructuredTool
from agents.extractor import extract_iocs
from dotenv import load_dotenv
from tools import (
    scan_url_virustotal_core,
    scan_domain_virustotal_core,
    scan_url_urlscan_core,
    check_ip_abuseipdb_core,
    follow_url_redirects_core,
)

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise ValueError("Missing GROQ_API_KEY in .env file")

llm = ChatGroq(api_key=GROQ_API_KEY, model_name="llama-3.3-70b-versatile", temperature=0)

# Wrap tools for LangChain
tools = [
    StructuredTool.from_function(
        func=scan_url_virustotal_core,
        name="scan_url_virustotal",
        description=(
            "Check a URL against VirusTotal for malicious or suspicious reputation. "
            "Use this for original URLs and final redirected URLs."
        ),
    ),
    StructuredTool.from_function(
        func=scan_domain_virustotal_core,
        name="scan_domain_virustotal",
        description=(
            "Check a domain against VirusTotal for malicious or suspicious reputation. "
            "Use this for sender domains, extracted domains, and final landing-page domains."
        ),
    ),
    StructuredTool.from_function(
        func=scan_url_urlscan_core,
        name="scan_url_urlscan",
        description=(
            "Submit a URL to URLScan.io sandbox for browser-based analysis, verdict, score, "
            "categories, and screenshot."
        ),
    ),
    StructuredTool.from_function(
        func=check_ip_abuseipdb_core,
        name="check_ip_abuseipdb",
        description=(
            "Check an IP address against AbuseIPDB for abuse confidence score, total reports, "
            "country, ISP, whitelist status, and last reported time."
        ),
    ),
    StructuredTool.from_function(
        func=follow_url_redirects_core,
        name="follow_url_redirects",
        description=(
            "Follow URL redirects using Playwright browser automation. "
            "Use this first for URLs to identify the final landing page."
        ),
    ),
]

prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            """You are PhishSleuth — an expert SOC phising investigationanalyst.

Your task is to investigate suspicious emails using available tools and produce an analyst-ready threat report.

You have access to these investigation tools:

Your task is to investigate suspicious emails using available tools and produce an analyst-ready threat report.
- follow_url_redirects: Use first for any URL to identify the final landing page and redirect chain.
- scan_url_virustotal: Use for original and final URLs to check reputation.
- scan_domain_virustotal: Use for domains found in URLs, sender addresses, or final redirect destinations.
- scan_url_urlscan: Use for suspicious URLs or final landing pages requiring browser-based sandbox analysis.
- check_ip_abuseipdb: Use for sender IPs or IPs found in headers or email content.

Investigation rules:
1. If a URL is present, follow redirects before reputation checks.
2. Check the final destination URL, not only the original URL.
3. Check domains separately when domain indicators are available.
4. Check IPs with AbuseIPDB when IP indicators are available.
5. If API results are clean but email language is suspicious, explain behavioral phishing indicators.
6. Do not overuse tools. Investigate thoroughly but efficiently.
7. Base the final verdict on both technical evidence and phishing behavior.
8. Distinguish spam from phishing. Spam is unsolicited bulk/promotional email without clear credential theft, malware delivery, impersonation, or financial fraud. Phishing is malicious social engineering intended to steal credentials, money, sensitive information, or deliver malware.

Final report format:
- Verdict: Phishing / Spam / Suspicious / Legitimate
- Confidence: High / Medium / Low
- Key Evidence
- Tool Findings
- Behavioral Analysis
- Recommended SOC Action
- Plain-English Explanation
""",
        ),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]
)

agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(
    agent=agent, 
    tools=tools, 
    verbose=True, 
    max_iterations=8,
    handle_parsing_errors=True,
)


def investigate_with_agent(email_text: str)-> str:
    print("\n PhishSleuth v2 — Agentic Investigation Starting...\n")

    # Extract IOCs first
    print(" Extracting IOCs...")
    iocs_raw = extract_iocs(email_text)
    try:
        iocs = json.loads(iocs_raw)
    except json.JSONDecodeError:
       raise ValueError(f"IOC extractor returned invalid JSON:\n{iocs_raw}")
    print(f"Found: {iocs}\n")

    #Agentic investigation using tools
    input_prompt = f"""
    Investigate this email for phishing indicators.
    
    Extracted IOCs:
    {json.dumps(iocs, indent=2)}

    Original Email:
    {email_text}
    
    Use the available tools to investigate relevant IOCs and produce a comprehensive SOC style threat analysis report.
    """

    result = agent_executor.invoke({"input": input_prompt})

    final_report = result["output"]

    print("\n" + "=" * 60)
    print("PHISHSLEUTH FINAL REPORT")
    print("=" * 60)
    print(result["output"])
    print("=" * 60)
    return final_report

if __name__ == "__main__":
    print(" PhishSleuth v2 — Agentic Phishing Investigator")
    print("=" * 60)
    print("1. Paste email text")
    print("2. Load .eml file")
    print("=" * 60)

    choice = input("Choose input method (1 or 2): ").strip()

    if choice == "1":
        print("\nPaste your email below. Type END on a new line when done:")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        email_text = "\n".join(lines)

    elif choice == "2":
        file_path = input("\nEnter path to .eml file: ").strip()
        from utils.parser import read_eml_file

        email_text = read_eml_file(file_path)

    else:
        print("Invalid choice.")
        exit()

    investigate_with_agent(email_text)

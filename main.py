import json

from agents.extractor import extract_iocs
from agents.vt_agent import check_virustotal
from agents.urlscan_agent import check_urlscan
from agents.abuseipdb_agent import check_abuseipdb
from agents.reporter import generate_report
from utils.browser import analyze_redirects
from utils.parser import read_eml_file


def investigate_email(email_text: str) -> str:
    print("Starting Phishing Investigation...\n")

    print("Step 1: Extracting IOCs from email...")

    iocs_raw = extract_iocs(email_text)

    try:
        iocs = json.loads(iocs_raw)
    except json.JSONDecodeError:
        print("IOC extraction failed. Raw LLM output:")
        print(iocs_raw)
        return ""

    print(
        f"Found: {len(iocs.get('urls', []))} URLs, "
        f"{len(iocs.get('ips', []))} IPs, "
        f"{len(iocs.get('domains', []))} domains\n"
    )

    print("Step 2: Following URL redirects with browser automation...")

    redirect_results = []
    expanded_urls = []

    for url in iocs.get("urls", []):
        redirect_info = analyze_redirects(url)
        redirect_results.append(redirect_info)

        final_url = redirect_info.get("final_url", url)
        expanded_urls.append(final_url)

        if redirect_info.get("redirected"):
            print(
                f"Redirect chain detected: "
                f"{len(redirect_info.get('redirect_chain', []))} hops"
            )
            print(f"Final destination: {final_url[:60]}...")
        else:
            print(f"No redirect: {url[:60]}...")

        if redirect_info.get("screenshot_path"):
            print(f"Screenshot saved: {redirect_info['screenshot_path']}")

    print("\nStep 3: Checking VirusTotal...")

    vt_results = []

    for url in expanded_urls:
        result = check_virustotal(url, "url")
        vt_results.append(result)

        print(f"{url[:50]}... — Malicious: {result.get('malicious', 0)}")

    for domain in iocs.get("domains", []):
        result = check_virustotal(domain, "domain")
        vt_results.append(result)

        print(f"{domain} — Malicious: {result.get('malicious', 0)}")

    print("\nStep 4: Scanning final URLs with URLScan...")

    urlscan_results = []

    for url in expanded_urls:
        result = check_urlscan(url)
        urlscan_results.append(result)

        print(f"{url[:50]}... — Score: {result.get('score', 'N/A')}")

    print("\nStep 5: Checking IPs with AbuseIPDB...")

    abuseipdb_results = []

    for ip in iocs.get("ips", []):
        result = check_abuseipdb(ip)
        abuseipdb_results.append(result)

        print(f"{ip} — Abuse Score: {result.get('abuse_confidence_score', 'N/A')}")

    print("\nStep 6: Generating Report...\n")

    report = generate_report(
        email_text,
        iocs,
        vt_results,
        urlscan_results,
        abuseipdb_results,
    )

    print("=" * 60)
    print("Phishing Investigation Report")
    print("=" * 60)
    print(report)
    print("=" * 60)

    return report


if __name__ == "__main__":
    print("PhishSleuth v1 — Fixed Pipeline Phishing Investigator")
    print("=" * 60)
    print("1. Quick test: Paste raw email text")
    print("2. Forensic mode: Load .eml file")
    print("3. Run built-in sample email")
    print("=" * 60)

    choice = input("Choose input method (1, 2, or 3): ").strip()

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
        email_text = read_eml_file(file_path)

    elif choice == "3":
        email_text = """
From: security@paypa1.com
Reply-To: hacker@gmail.com
Subject: Urgent: Your account has been compromised!

Dear Customer,

We have detected suspicious activity on your PayPal account.
Your account will be suspended within 24 hours unless you verify immediately.

Click here to verify: http://paypal-secure-login.xyz/verify

Your IP: 185.220.101.45

PayPal Security Team
"""

    else:
        print("Invalid choice.")
        exit()

    investigate_email(email_text)

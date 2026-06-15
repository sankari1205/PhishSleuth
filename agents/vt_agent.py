import os
import requests
from agents.abuseipdb_agent import ABUSEIPDB_API_KEY
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_virustotal(ioc, ioc_type):

    if not VT_API_KEY:
        return {"ioc": ioc, "error": "Missing VirusTotal API key"}
    """
    ioc_type: 'url', 'ip', or 'domain'
    """
    headers = {"x-apikey": VT_API_KEY}

    if ioc_type == "url":

        import base64

        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    elif ioc_type == "ip":

        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"

    elif ioc_type == "domain":

        endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:

        data = response.json()

        stats = (
            data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        )

        return {
            "ioc": ioc,
            "type": ioc_type,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("undetected", 0),
        }

    else:

        return {"ioc": ioc, "error": f"Status {response.status_code}"}

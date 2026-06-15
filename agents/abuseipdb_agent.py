import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"ip": ip, "error": "Missing AbuseIPDB API key"}

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=15
    )

    if response.status_code == 200:
        data = response.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported": data.get("lastReportedAt", "Never"),
        }

    else:
        return {"ip": ip, "error": f"Status {response.status_code}"}

import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")


def check_urlscan(url):
    if not URLSCAN_API_KEY:
        return {"url": url, "error": "Missing URLScan API key"}

    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

    payload = {"url": url, "visibility": "public"}

    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, json=payload
    )

    if response.status_code != 200:

        return {"url": url, "error": f"Submission failed: {response.status_code}"}

    scan_uuid = response.json().get("uuid")

    time.sleep(10)

    result = requests.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/")

    if result.status_code == 200:

        data = result.json()

        return {
            "url": url,
            "malicious": data.get("verdicts", {})
            .get("overall", {})
            .get("malicious", False),
            "score": data.get("verdicts", {}).get("overall", {}).get("score", 0),
            "categories": data.get("verdicts", {})
            .get("overall", {})
            .get("categories", []),
            "screenshot": data.get("task", {}).get("screenshotURL", ""),
        }

    else:

        return {"url": url, "error": "Result not ready"}

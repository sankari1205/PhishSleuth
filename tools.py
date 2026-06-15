import fastmcp
from agents.vt_agent import check_virustotal
from agents.urlscan_agent import check_urlscan
from agents.abuseipdb_agent import check_abuseipdb
from utils.browser import analyze_redirects

mcp = fastmcp.FastMCP("PhishSleuth")

def scan_url_virustotal_core(url: str) -> dict:
    """Core function to check a URL using VirusTotal."""
    return check_virustotal(url, "url")


def scan_domain_virustotal_core(domain: str) -> dict:
    """Core function to check a domain using VirusTotal."""
    return check_virustotal(domain, "domain")


def scan_url_urlscan_core(url: str) -> dict:
    """Core function to submit a URL to URLScan.io."""
    return check_urlscan(url)


def check_ip_abuseipdb_core(ip: str) -> dict:
    """Core function to check an IP using AbuseIPDB."""
    return check_abuseipdb(ip)


def follow_url_redirects_core(url: str) -> dict:
    """Core function to follow redirects using Playwright."""
    return analyze_redirects(url)

@mcp.tool()
def scan_url_virustotal(url: str) -> dict:
    """Check a URL or domain against VirusTotal for malicious reputation."""
    return check_virustotal(url, "url")


@mcp.tool()
def scan_domain_virustotal(domain: str) -> dict:
    """Check a domain against VirusTotal for malicious reputation."""
    return check_virustotal(domain, "domain")


@mcp.tool()
def scan_url_urlscan(url: str) -> dict:
    """Submit a URL to URLScan sandbox for behavioral analysis and screenshot."""
    return check_urlscan(url)


@mcp.tool()
def check_ip_abuseipdb(ip: str) -> dict:
    """Check an IP address against AbuseIPDB for abuse reports."""
    return check_abuseipdb(ip)


@mcp.tool()
def follow_url_redirects(url: str) -> dict:
    """Follow URL redirect chain using Playwright browser automation."""
    return analyze_redirects(url)

if __name__ == "__main__":
    mcp.run()
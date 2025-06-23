# app.py

import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from urllib.parse import urlparse
import requests
import json
import re

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app) # Enable CORS for cross-origin requests from your HTML frontend

# --- Configuration (IMPORTANT: Replace with your actual API key) ---
# For production, consider using environment variables for API keys:
# GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "YOUR_GOOGLE_SAFE_BROWSING_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY" # Replace this!
GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GOOGLE_SAFE_BROWSING_API_KEY

# --- Simple Blacklist/Whitelist (can be expanded and loaded from files or a database) ---
KNOWN_PHISHING_DOMAINS = [
    "example-phishing.com",
    "malicious-site.net",
    "bad-login.xyz",
    "paypal-verification.ru", # Example of a suspicious domain
]
KNOWN_LEGIT_DOMAINS = [
    "google.com",
    "microsoft.com",
    "amazon.com",
    "github.com",
    "openai.com",
]

# --- Helper Functions (Copied from your previous scanner code) ---

def is_whitelisted(domain):
    """
    Checks if the given domain is in the predefined whitelist.
    Domains in this list are considered safe without further checks.
    """
    return domain.lower() in [d.lower() for d in KNOWN_LEGIT_DOMAINS]

def is_blacklisted(domain):
    """
    Checks if the given domain is in the predefined blacklist.
    Domains in this list are considered malicious.
    """
    return domain.lower() in [d.lower() for d in KNOWN_PHISHING_DOMAINS]

def check_google_safe_browsing(url):
    """
    Checks a URL against Google Safe Browsing API for known threats.
    Returns (True, matches_details) if unsafe, (False, None) otherwise.
    Requires a valid GOOGLE_SAFE_BROWSING_API_KEY.
    """
    threat_info = {
        "client": {
            "clientId": "brainwave-matrix-phishing-scanner", # Your application name
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    headers = {"Content-Type": "application/json"}
    
    if not GOOGLE_SAFE_BROWSING_API_KEY or GOOGLE_SAFE_BROWSING_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        print("[API Warning] Google Safe Browsing API key not configured. Skipping API check.")
        return False, None

    try:
        print(f"[{url}] Querying Google Safe Browsing API...")
        response = requests.post(GOOGLE_SAFE_BROWSING_API_URL, json=threat_info, headers=headers, timeout=15)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        
        if "matches" in data and len(data["matches"]) > 0:
            return True, data["matches"]
        return False, None
    except requests.exceptions.RequestException as e:
        print(f"[API Error] Failed to connect to Google Safe Browsing API for {url}: {e}")
        return False, None
    except json.JSONDecodeError:
        print(f"[API Error] Could not decode JSON response from Google Safe Browsing API for {url}.")
        return False, None

def analyze_url_heuristics(url):
    """
    Performs heuristic analysis on the URL to detect suspicious patterns.
    Returns a dictionary of detected suspicious findings.
    """
    findings = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    if not domain:
        return {"invalid_url": "URL does not contain a valid domain."}

    # 1. Typosquatting/Homoglyph Detection (Basic Example)
    common_targets = ["google", "microsoft", "apple", "amazon", "paypal", "bank"]
    for target in common_targets:
        if len(domain) > len(target) + 2 and target in domain:
            if re.search(r'0|o|1|l|i|\|', domain):
                findings["typosquatting_suspect"] = f"Domain '{domain}' might be typosquatting '{target}'."
                break

    # 2. Excessive Subdomains
    subdomains = domain.split('.')
    effective_subdomain_count = len(subdomains) - 2 
    if subdomains[0].lower() == 'www':
        effective_subdomain_count -= 1 
        
    if effective_subdomain_count > 2:
        findings["excessive_subdomains"] = f"URL contains {effective_subdomain_count} significant subdomains."

    # 3. IP Address in Hostname
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        findings["ip_address_in_hostname"] = f"URL uses IP address '{domain}' as hostname."

    # 4. Misleading Characters in URL Path or Query
    if '@' in parsed_url.netloc and parsed_url.netloc.split('@')[1] != "":
         findings["at_symbol_in_netloc"] = "URL contains '@' symbol in network location, potentially misleading."

    if re.search(r'%[0-9a-fA-F]{2}', url) and len(re.findall(r'%[0-9a-fA-F]{2}', url)) > 5:
        findings["excessive_encoding"] = "URL contains excessive URL encoding."

    # 5. HTTP vs. HTTPS
    if parsed_url.scheme == 'http':
        findings["http_scheme"] = "URL uses HTTP instead of HTTPS."
        
    # 6. Long URL (potential obfuscation)
    if len(url) > 100:
        findings["long_url"] = "URL is unusually long (over 100 characters)."

    return findings

# --- Main Scanner Logic Function (adapted for web output) ---
def perform_scan(url):
    """
    Main function to scan a URL for phishing indicators, returning results for web display.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if not domain:
        return {
            "status": "INVALID",
            "message": "The provided input is not a valid URL or is missing a domain.",
            "details": []
        }

    details = []

    # 1. Whitelist Check
    if is_whitelisted(domain):
        details.append(f"Domain '{domain}' is explicitly whitelisted.")
        return {
            "status": "SAFE",
            "message": f"Domain '{domain}' is explicitly whitelisted. Considered SAFE.",
            "details": details
        }

    # 2. Blacklist Check
    if is_blacklisted(domain):
        details.append(f"Domain '{domain}' is explicitly blacklisted.")
        return {
            "status": "MALICIOUS",
            "message": f"Domain '{domain}' is explicitly blacklisted. Considered MALICIOUS.",
            "details": details
        }

    # 3. Google Safe Browsing API Check
    is_unsafe, matches = check_google_safe_browsing(url)
    if is_unsafe:
        threat_details = []
        for match in matches:
            threat_details.append(f"Threat Type: {match.get('threatType', 'N/A')}, Platform: {match.get('platformType', 'N/A')}")
        details.append(f"Flagged by Google Safe Browsing API: {'; '.join(threat_details)}")
        return {
            "status": "MALICIOUS",
            "message": "Flagged by Google Safe Browsing API. Considered MALICIOUS.",
            "details": details
        }

    # 4. Heuristic Analysis
    heuristic_findings = analyze_url_heuristics(url)
    if heuristic_findings:
        details.append("Heuristic patterns detected:")
        for finding_type, description in heuristic_findings.items():
            details.append(f"- {finding_type.replace('_', ' ').title()}: {description}")
        return {
            "status": "SUSPICIOUS",
            "message": "Suspicious patterns detected. Please exercise caution.",
            "details": details
        }

    details.append(f"No significant phishing indicators found for '{url}'.")
    return {
        "status": "SAFE",
        "message": "No obvious phishing indicators found. Considered SAFE.",
        "details": details
    }

# --- Flask Routes ---

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """API endpoint to receive URL and return scan results."""
    data = request.get_json()
    url_to_scan = data.get('url')

    if not url_to_scan:
        return jsonify({
            "status": "ERROR",
            "message": "No URL provided.",
            "details": []
        }), 400

    print(f"Received scan request for: {url_to_scan}")
    scan_results = perform_scan(url_to_scan)
    return jsonify(scan_results)

# --- Run the Flask App ---
if __name__ == '__main__':
    # You can specify a host and port, e.g., debug=True will auto-reload on code changes
    app.run(debug=True, host='0.0.0.0', port=5000)

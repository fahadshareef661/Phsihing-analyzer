import email          
import re             
import requests       
import time           

VT_API_KEY = "5707c7f3f0c27cabcc46e6de85e25b130b7123984f70f057d78099ba5e4f11ce"

 #EMAIL PARSER

def parse_email(file_path):
    print("\n" + "="*55)
    print("       PHISHING EMAIL ANALYZER — by Fahad")
    print("="*55)

    with open(file_path, "r", errors="ignore") as f:
        raw_email = f.read()

    # Parse the raw email using Python's built-in email library
    msg = email.message_from_string(raw_email)

    print("\n[+] ---- EMAIL HEADER ANALYSIS ----")
    print(f"    From       : {msg.get('From', 'Not Found')}")
    print(f"    To         : {msg.get('To', 'Not Found')}")
    print(f"    Subject    : {msg.get('Subject', 'Not Found')}")
    print(f"    Date       : {msg.get('Date', 'Not Found')}")
    print(f"    Message-ID : {msg.get('Message-ID', 'Not Found')}")
    print(f"    Received   : {msg.get('Received', 'Not Found')}")

    # Extract the email body (plain text)
    body = ""
    if msg.is_multipart():
        # If email has multiple parts (HTML + text), loop through them
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    # Combine headers + body for IOC extraction
    full_content = raw_email + body
    return full_content, msg.get('From', '')



# BLOCK 2 — IOC EXTRACTOR
# Uses regex to pull out IPs and URLs

def extract_iocs(content):
    print("\n[+] ---- IOC EXTRACTION ----")

    # Regex pattern to find IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Regex pattern to find URLs (http and https)
    url_pattern = r'https?://[^\s<>"\'\\]+'

    # findall() returns a list of all matches
    ips = list(set(re.findall(ip_pattern, content)))
    urls = list(set(re.findall(url_pattern, content)))

    # Filter out common false positives (version numbers like 1.0.0.1)
    # A real IP won't have all numbers under 10
    ips = [ip for ip in ips if not all(int(x) < 2 for x in ip.split('.'))]

    print(f"\n    IPs Found  : {ips if ips else 'None'}")
    print(f"    URLs Found : {urls if urls else 'None'}")

    return ips, urls


# ─────────────────────────────────────────────
# BLOCK 3A — VIRUSTOTAL IP CHECKER
# Sends IP to VirusTotal and gets threat verdict
# ─────────────────────────────────────────────
def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            return malicious, suspicious, total
        else:
            return None, None, None
    except Exception as e:
        print(f"    [!] Error checking IP {ip}: {e}")
        return None, None, None


# ─────────────────────────────────────────────
# BLOCK 3B — VIRUSTOTAL URL CHECKER
# Sends URL to VirusTotal and gets threat verdict
# ─────────────────────────────────────────────
def check_url_virustotal(url_to_check):
    import base64
    # VirusTotal requires URL to be base64 encoded
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            return malicious, suspicious, total
        else:
            return None, None, None
    except Exception as e:
        print(f"    [!] Error checking URL: {e}")
        return None, None, None


# ─────────────────────────────────────────────
# BLOCK 4 — THREAT REPORT GENERATOR
# Prints a clean final verdict
# ─────────────────────────────────────────────
def generate_report(ips, urls):
    print("\n[+] ---- VIRUSTOTAL THREAT ANALYSIS ----")

    threat_score = 0  # we'll use this to calculate overall verdict

    # Check each IP
    if ips:
        print("\n    [IPs]")
        for ip in ips:
            malicious, suspicious, total = check_ip_virustotal(ip)
            if malicious is not None:
                verdict = "🔴 MALICIOUS" if malicious > 0 else ("🟡 SUSPICIOUS" if suspicious > 0 else "🟢 CLEAN")
                print(f"    IP : {ip}")
                print(f"         Malicious  : {malicious}/{total} vendors")
                print(f"         Suspicious : {suspicious}/{total} vendors")
                print(f"         Verdict    : {verdict}")
                threat_score += malicious + suspicious
            else:
                print(f"    IP : {ip} — Could not retrieve data")
            time.sleep(15)  # free API allows 4 requests/min, so wait 15 sec

    # Check each URL
    if urls:
        print("\n    [URLs]")
        for url in urls:
            malicious, suspicious, total = check_url_virustotal(url)
            if malicious is not None:
                verdict = "🔴 MALICIOUS" if malicious > 0 else ("🟡 SUSPICIOUS" if suspicious > 0 else "🟢 CLEAN")
                print(f"    URL: {url}")
                print(f"         Malicious  : {malicious}/{total} vendors")
                print(f"         Suspicious : {suspicious}/{total} vendors")
                print(f"         Verdict    : {verdict}")
                threat_score += malicious + suspicious
            else:
                print(f"    URL: {url} — Could not retrieve data")
            time.sleep(15)

    # Final overall verdict based on threat score
    print("\n" + "="*55)
    print("              FINAL VERDICT")
    print("="*55)
    if threat_score == 0:
        print("  🟢 LOW RISK   — No threats detected")
    elif threat_score <= 5:
        print("  🟡 MEDIUM RISK — Suspicious indicators found")
    else:
        print("  🔴 HIGH RISK  — Malicious email confirmed!")
    print(f"  Total Threat Score : {threat_score}")
    print("="*55)
    print("\n[+] Analysis complete. Document findings in your incident report.\n")


# ─────────────────────────────────────────────
# MAIN — Entry point of the script
# ─────────────────────────────────────────────
def main():
    # Ask user for the .eml file path
    file_path = input("\n[?] Enter path to .eml file (e.g. sample.eml): ").strip()

    # Step 1: Parse the email
    content, sender = parse_email(file_path)

    # Step 2: Extract IOCs
    ips, urls = extract_iocs(content)

    # Step 3: Check with VirusTotal and generate report
    if ips or urls:
        print("\n[*] Checking IOCs against VirusTotal...")
        print("[*] Note: Free API has rate limits, please wait between checks...")
        generate_report(ips, urls)
    else:
        print("\n[!] No IOCs found in this email.")


# Run the script
if __name__ == "__main__":
    main()
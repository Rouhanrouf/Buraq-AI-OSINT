import ollama
import subprocess
import httpx
import socket
import ssl
import concurrent.futures
import os
from playwright.sync_api import sync_playwright
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

# --- 1. THE EYE (Visual Verification) ---
def capture_screenshot(subdomain):
    if not os.path.exists("Buraq_Screenshots"):
        os.makedirs("Buraq_Screenshots")
    filename = f"Buraq_Screenshots/{subdomain.replace('.', '_')}.png"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            try:
                page.goto(f"https://{subdomain}", timeout=10000, wait_until="networkidle")
            except:
                page.goto(f"http://{subdomain}", timeout=10000, wait_until="networkidle")
            page.screenshot(path=filename)
            browser.close()
            return filename
    except: return None

# --- 2. THE CVE-MAPPER (Intelligence) ---
def check_vulnerabilities(banner):
    vdb = {
        "Apache/2.4.6": "CVE-2019-0211 (Privilege Escalation)",
        "PHP/7.0": "CVE-2019-11043 (RCE)",
        "OpenSSH_9.6": "CVE-2024-6387 (RegreSSHion)",
        "Microsoft-IIS/10.0": "IIS 10 Hardening Needed",
        "awselb/2.0": "AWS Infrastructure Detected"
    }
    for version, cve in vdb.items():
        if version in banner: return cve
    return "No immediate CVE matches"

# --- 3. THE GHOST-FINDER & SHIELD ---
def brute_force_subdomains(domain):
    wordlist = ["dev", "api", "admin", "vpn", "mail", "portal", "git", "test", "db", "backup"]
    found = []
    print(f"[*] BURAQ: Initiating Multithreaded Ghost-Finder...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        def check(w):
            sub = f"{w}.{domain}"
            try:
                socket.gethostbyname(sub); return sub
            except: return None
        futures = [ex.submit(check, w) for w in wordlist]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: found.append(res)
    return found

def identify_waf(subdomain):
    try:
        r = httpx.get(f"https://{subdomain}", timeout=3.0, verify=False)
        h = str(r.headers).lower()
        if "cloudflare" in h: return "Cloudflare"
        if "f5" in h: return "F5 BIG-IP"
        if "awselb" in h: return "AWS WAF"
    except: pass
    return "No WAF Detected"

# --- 4. THE INTERROGATOR ---
def grab_banner(subdomain, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.5)
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=subdomain) as ss:
                    ss.connect((subdomain, port))
                    ss.sendall(f"HEAD / HTTP/1.1\r\nHost: {subdomain}\r\nConnection: close\r\n\r\n".encode())
                    return ss.recv(1024).decode(errors='ignore').split('\r\n')[0]
            else:
                s.connect((subdomain, port))
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {subdomain}\r\nConnection: close\r\n\r\n".encode())
                return s.recv(1024).decode(errors='ignore').split('\r\n')[0]
    except: return "Filtered"

# --- 5. THE SCRIBE (The Repair: Bulletproof PDF Wrapping) ---
def generate_pdf(domain, content):
    filename = f"Buraq_{domain.replace('.', '_')}_FINAL.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title & Subtitle
    story.append(Paragraph(f"<b>PROJECT BURAQ v10.2: FINAL INTEL</b>", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Lead Researcher: ETErNA | Target: {domain}", styles['Normal']))
    story.append(Spacer(1, 24))

    for line in content.split('\n'):
        if line.strip():
            # Robust bolding: Splits by ** and wraps correctly to avoid parse errors
            parts = line.split('**')
            clean_line = ""
            for i, part in enumerate(parts):
                if i % 2 == 1:
                    clean_line += f"<b>{part}</b>"
                else:
                    clean_line += part
            
            try:
                story.append(Paragraph(clean_line, styles['Normal']))
            except:
                # Emergency Fallback: If tags still fail, strip them and print plain text
                story.append(Paragraph(line.replace('**', ''), styles['Normal']))
            story.append(Spacer(1, 6))

    doc.build(story)
    print(f"\n[✔] Bulletproof PDF saved: {filename}")

# --- 6. THE BRAIN ---
def buraq_scout(domain):
    print(f"[🚀] BURAQ: Launching v10.2 FINAL MISSION...")
    osint_leads = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True).stdout.splitlines()
    ghost_leads = brute_force_subdomains(domain)
    all_leads = list(set(osint_leads + ghost_leads))
    
    technical_log = []
    print(f"[*] Deep Scanning & Photographing top leads...")
    for sub in all_leads[:12]:
        shield = identify_waf(sub)
        screenshot_path = capture_screenshot(sub)
        port_info = []
        for p in [80, 443]:
            banner = grab_banner(sub, p)
            if "Filtered" not in banner:
                cve = check_vulnerabilities(banner)
                port_info.append(f"Port {p} ({banner}) -> {cve}")
        
        log_entry = f"- {sub} | Shield: {shield} | Photo: {screenshot_path if screenshot_path else 'Blocked'} | {', '.join(port_info)}"
        print(log_entry); technical_log.append(log_entry)

    prompt = f"Analyze these technical results for {domain}:\n" + "\n".join(technical_log) + "\nPrioritize high-risk leads."
    try:
        response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': prompt}])
        print("\n" + "="*50 + "\n[!] BURAQ FINAL INTELLIGENCE\n" + "="*50 + "\n" + response['message']['content'])
        generate_pdf(domain, response['message']['content'])
    except Exception as e: print(f"[!] Brain Error: {e}")

if __name__ == "__main__":
    target = input("Enter target domain: ").strip()
    if target: buraq_scout(target)

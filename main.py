import subprocess
import requests
import time
import sys
from tqdm import tqdm
from termcolor import colored

def print_banner():
    banner = r"""
     _            _     ____                                  
    | | __ _  ___| | __/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
 _  | |/ _` |/ __| |/ /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |_| | (_| | (__|   <  ___) | (_| (_| | | | | | | |  __/ |   
 \___/ \__,_|\___|_|\_\|____/ \___\__,_|_| |_|_| |_|\___|_|    
    """
    print(colored(banner, "cyan"))
    print(colored("JackScanner - A Clickjacking Vulnerability Detection Tool", "yellow"))
    print(colored("Made by davycipher", "green"))
    print("=" * 60)

def find_subdomains(domain):
    print(colored("[*] Enumerating subdomains...", "magenta"))
    try:
        output = subprocess.check_output(["subfinder", "-d", domain, "-silent"], text=True)
        subdomains = output.splitlines()
        print(f"\033[32m[+] Found {len(subdomains)} subdomains.\033[0m")
        return subdomains
    except FileNotFoundError:
        print(colored("[!] Subfinder is not installed. Install it using 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'", "red"))
        return []

def check_live_subdomains(subdomains):
    print(colored("[*] Testing for live subdomains...", "magenta"))
    live_subdomains = []
    for subdomain in tqdm(subdomains, desc="Checking live subdomains", ncols=100, colour="green"):
        for scheme in ["http", "https"]:
            url = f"{scheme}://{subdomain}"
            try:
                response = requests.head(url, timeout=5)
                if response.status_code < 400:
                    live_subdomains.append(url)
            except requests.RequestException:
                pass
    return live_subdomains

def check_clickjacking(subdomains):
    print(colored("\n[*] Checking for clickjacking vulnerabilities...", "magenta"))
    vulnerable_targets = []
    for url in tqdm(subdomains, desc="Testing for clickjacking", ncols=100, colour="red"):
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
                vulnerable_targets.append(url)
                print(colored(f"[VULNERABLE] {url} - No protection against clickjacking", "red"))
        except requests.RequestException:
            pass
    return vulnerable_targets

if __name__ == "__main__":
    print_banner()

    domain = input(colored("Enter the main domain (e.g., nokia.com): ", "yellow")).strip()
    
    subdomains = find_subdomains(domain)
    if subdomains:
        print(colored("[*] Starting live subdomain checks...", "blue"))
        live_subdomains = check_live_subdomains(subdomains)
    else:
        print(colored("[!] No subdomains found.", "red"))
        live_subdomains = []

    if live_subdomains:
        print(colored("\n[*] Starting clickjacking vulnerability checks...", "blue"))
        vulnerable_targets = check_clickjacking(live_subdomains)
    else:
        print(colored("[!] No live subdomains found. Exiting.", "red"))
        sys.exit(1)

    print("\n" + "=" * 60)
    print(colored("Summary:", "yellow"))
    print(colored("[+] Live Subdomains:", "green"))
    for live in live_subdomains:
        print(f"  - {live}")

    print(colored("\n[+] Clickjacking Vulnerable Websites:", "red"))
    if vulnerable_targets:
        for vuln in vulnerable_targets:
            print(f"  - {vuln}")
    else:
        print(colored("  All tested websites are protected.", "green"))
    print("=" * 60)

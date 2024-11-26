import subprocess
import requests
import sys
import time
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
    print("="*60)

def find_subdomains(domain):
    print(colored("[*] Enumerating subdomains...", "magenta"))
    try:
        output = subprocess.check_output(["subfinder", "-d", domain, "-silent"], text=True)
        subdomains = output.splitlines()
        print(f"[+] Found {len(subdomains)} subdomains.")
        return subdomains
    except FileNotFoundError:
        print(colored("[!] Subfinder is not installed. Install it using 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'", "red"))
        return []

def check_live_subdomains(subdomains):
    print(colored("[*] Testing for live subdomains...", "magenta"))
    live_subdomains = []
    for subdomain in subdomains:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{subdomain}"
            try:
                response = requests.head(url, timeout=5)
                if response.status_code < 400:
                    live_subdomains.append(url)
                    print(colored(f"[LIVE] {url}", "green"))
            except requests.RequestException:
                pass
    return live_subdomains

def check_clickjacking(subdomains):
    print(colored("\n[*] Checking for clickjacking vulnerabilities...", "magenta"))
    for url in subdomains:
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            if 'X-Frame-Options' in headers or 'Content-Security-Policy' in headers:
                print(colored(f"[SAFE] {url} - Protected against clickjacking", "green"))
            else:
                print(colored(f"[VULNERABLE] {url} - No protection against clickjacking", "red"))
        except requests.RequestException as e:
            print(colored(f"[ERROR] {url} - {e}", "yellow"))

def loading_bar():
    for i in range(4):
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("\n")

if __name__ == "__main__":
    print_banner()

    domain = input(colored("Enter the main domain (e.g., nokia.com): ", "yellow")).strip()
    
    subdomains = find_subdomains(domain)
    
    if subdomains:
        loading_bar()
        live_subdomains = check_live_subdomains(subdomains)
    else:
        print(colored("[!] No subdomains found.", "red"))
        live_subdomains = []

    if live_subdomains:
        check_clickjacking(live_subdomains)
    else:
        print(colored("[!] No live subdomains found. Exiting.", "red"))

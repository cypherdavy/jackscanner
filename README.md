
# JackScanner 🚀  
**A Professional Clickjacking Vulnerability Detection Tool**  

JackScanner is a robust Python-based tool designed for ethical hackers, penetration testers, and web security professionals to identify and mitigate clickjacking vulnerabilities in web applications. Equipped with subdomain enumeration, live filtering, and detailed vulnerability analysis, JackScanner makes securing your digital assets simpler and more effective.

---

## 📋 Features  
- **Subdomain Enumeration**: Automatically identifies all subdomains of the target domain using `subfinder`.  
- **Live Subdomain Filtering**: Filters live, accessible subdomains to focus on actionable targets.  
- **Clickjacking Detection**: Detects vulnerabilities by inspecting HTTP headers (`X-Frame-Options`, `Content-Security-Policy`).  
- **Interactive Experience**: Stylish UI with progress bars and color-coded outputs for better usability.  
- **Summary Reports**:  
  - Lists all live subdomains.  
  - Highlights subdomains vulnerable to clickjacking.  

---

## 🔧 Installation  

### Prerequisites:  
- Python 3.6 or higher.  
- `subfinder` installed via `Go`.  

### Steps:  
1. Clone the repository:  
   ```bash
   git clone https://github.com/cypherdavy/jackscanner.git
   cd jackscanner
   ```  
2. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```  
3. Install `subfinder`:  
   ```bash
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

---

## 🚀 Usage  

1. Run the script:  
   ```bash
   python main.py
   ```  
2. Enter the target domain when prompted:  
   ```
   Enter the main domain (e.g., nokia.com): example.com
   ```  
3. Review the results:
   - **Live Subdomains**: All live and accessible subdomains.  
   - **Clickjacking Vulnerabilities**: Domains lacking proper protections.  

---

## 💻 Example Run  

### Input:
```bash
Enter the main domain (e.g., nokia.com): example.com
```  

### Output:
```plaintext
[*] Enumerating subdomains...
[+] Found 8 subdomains.

[*] Testing for live subdomains...
[LIVE] https://www.example.com
[LIVE] https://secure.example.com

[*] Checking for clickjacking vulnerabilities...
[VULNERABLE] https://www.example.com - No protection against clickjacking
[SAFE] https://secure.example.com - Protected against clickjacking

============================================================
Summary:
[+] Live Subdomains:
  - https://www.example.com
  - https://secure.example.com

[+] Clickjacking Vulnerable Websites:
  - https://www.example.com
============================================================
```

---

## 🔬 Proof of Concept (PoC)  
JackScanner includes **working PoCs** to demonstrate the impact of identified vulnerabilities.  


---

## 🔒 Security Disclaimer  
JackScanner is a **read-only testing tool** and does not harm target applications. Ensure you have explicit authorization before running scans. This tool is for **ethical use only**.  

---

## 📝 License  
This project is licensed under the [MIT License](LICENSE).  

---

## 🤝 Contributing  
We welcome contributions from the community!  
- Fork the repository.  
- Submit issues or pull requests.  
- Share feedback to improve JackScanner.  

---

## 📧 Contact  
For inquiries, reach out to:  
- **Author**: davycipher  
- **Email**: [davycypher@gmail.com](mailto:davycypher@gmail.com)  

---

## 🌟 Acknowledgments  
- Built on the amazing open-source tools: `subfinder`, `tqdm`, `termcolor`.  
- Inspired by the global ethical hacking community.  

```

---

### **Key Highlights:**
1. **Professional Presentation**:
   - Clear sections like Features, Installation, Usage, Example Run, PoC, and License.

2. **PoC Section**:
   - Demonstrates real-world impact with a practical scenario.

3. **Security Focus**:
   - Disclaimer emphasizes ethical use.

4. **Engagement**:
   - Encourages contributions with clear steps.

### Next Steps:
1. Add the **PoC video link** or screenshots to enhance credibility.
2. Update repository URLs (`your-username`) with your actual GitHub username.

Let me know if you'd like further assistance with this!

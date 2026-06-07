# Web Security Scanner Tool

A lightweight Python tool for detecting common web vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), and Path Traversal.

## 🚀 Features

- **SQL Injection Detection** - Tests for classic SQLi payloads and error-based detection
- **XSS Detection** - Identifies reflected XSS vulnerabilities
- **Path Traversal Detection** - Checks for directory traversal vulnerabilities
- **Automatic Parameter Extraction** - Parses URL parameters automatically
- **Manual Parameter Input** - Fallback option for URLs without parameters
- **Color-Coded Console Output** - Easy-to-read scan results
- **Detailed Reports** - Comprehensive vulnerability summary

## 📋 Prerequisites

- Python 3.6+
- `requests` library
- `urllib3` library

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web-security-scanner.git
cd web-security-scanner

# Install required dependencies
pip install requests
```

## 💻 Usage

### Basic Usage

```bash
python payload_injection.py
```

### Example Run

```
============================================================
         Web Security Scanner Tool v1.0
============================================================

[+] Supported tests:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Path Traversal
------------------------------------------------------------

[?] Enter target URL: https://example.com/page?id=1&search=test

[+] Target: https://example.com/page?id=1&search=test
[+] Found 2 parameter(s) to test: id, search

============================================================
[*] Starting security scan...
============================================================

==================================================
[>>] Testing parameter: id
==================================================

  [*] Testing SQLi on parameter: id
    [!] SQLi FOUND! Payload: ' OR '1'='1

  [*] Testing XSS on parameter: id
    [✓] No XSS found on id

  [*] Testing Path Traversal on parameter: id
    [✓] No Path Traversal found on id
```

## 🎯 Test Payloads

### SQL Injection
- `'`
- `''`
- `' OR '1'='1`
- `' OR 1=1--`
- `'; DROP TABLE users--`
- `" OR "1"="1`

### XSS (Cross-Site Scripting)
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `javascript:alert(1)`
- `<svg onload=alert(1)>`

### Path Traversal
- `../../../etc/passwd`
- `..\..\..\windows\win.ini`
- `%2e%2e%2f%2e%2e%2fetc/passwd`

## 📊 Sample Output Report

```
============================================================
              SCAN REPORT
============================================================

[!] Found 2 vulnerability(s):

  1. Type: SQL Injection
     Parameter: id
     Payload: ' OR '1'='1
     Evidence: SQL error message in response

  2. Type: Reflected XSS
     Parameter: search
     Payload: <script>alert(1)</script>
     Evidence: Payload reflected in response

============================================================
[*] Scan completed!
============================================================
```

## ⚠️ Important Notes

- **Educational Purpose Only** - This tool is designed for security testing on authorized systems only
- **Always Get Permission** - Only scan websites you own or have explicit permission to test
- **No Exploitation** - The tool only detects vulnerabilities, it does not exploit them
- **Rate Limiting** - Consider implementing delays between requests for production testing

## 🔒 Legal Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized scanning of websites without permission is illegal. The author assumes no liability for misuse of this tool. Always ensure you have written permission before testing any system.

## 🛠️ Customization

### Adding New Payloads

Edit the `payloads` dictionary in the `SecurityScanner` class:

```python
self.payloads = {
    "SQLi": ["your", "new", "payloads"],
    "XSS": ["your", "new", "payloads"],
    "PathTraversal": ["your", "new", "payloads"]
}
```

### Adjusting Timeout

Change the timeout value in the `requests.get()` calls:

```python
resp = requests.get(test_url, timeout=10, verify=False)  # 10 seconds timeout
```

## 🐛 Known Limitations

- Does not test POST parameters
- No CSRF detection
- Limited blind SQL injection detection
- No authentication handling
- No rate limiting or delay between requests


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Contact

[sayhellotohacker1@gmail.com] 


---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally!

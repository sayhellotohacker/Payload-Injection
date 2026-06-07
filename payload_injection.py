from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
import sys
from colorama import Fore, Style, init

init(autoreset=True)


class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = {
            "SQLi": ["'", "''", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            "PathTraversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc/passwd"]
        }
        self.results = []

    def test_sql_injection(self, url, param_name, original_value):
        """Test SQL injection payloads"""
        for payload in self.payloads["SQLi"]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(new_url, timeout=5)
                # Detection logic
                sql_errors = ["sql", "mysql", "syntax", "ora-", "postgres", "unclosed"]
                if any(error in resp.text.lower() for error in sql_errors):
                    self.results.append({
                        "type": "SQL Injection",
                        "url": new_url,
                        "payload": payload,
                        "evidence": f"SQL error detected"
                    })
                    print(f"{Fore.RED}[!] SQLi Found: {payload}")
                else:
                    print(f"{Fore.GREEN}[-] No SQLi: {payload}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error: {e}")

    def test_xss(self, url, param_name, original_value):
        """Test XSS payloads"""
        for payload in self.payloads["XSS"]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(new_url, timeout=5)
                if payload in resp.text:
                    self.results.append({
                        "type": "XSS (Reflected)",
                        "url": new_url,
                        "payload": payload,
                        "evidence": "Payload reflected in response"
                    })
                    print(f"{Fore.RED}[!] XSS Found: {payload}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error: {e}")

    def run(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        if not params:
            print(f"{Fore.RED}[!] No parameters found in URL")
            return

        for param in params:
            original_value = params[param][0]
            print(f"{Fore.CYAN}[*] Testing parameter: {param}")
            self.test_sql_injection(self.target_url, param, original_value)
            self.test_xss(self.target_url, param, original_value)

        self.generate_report()

    def generate_report(self):
        print(f"\n{Fore.CYAN}{'=' * 50}")
        print(f"{Fore.CYAN}[+] Scan Complete")
        print(f"{Fore.CYAN}{'=' * 50}")

        if not self.results:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found")
        else:
            print(f"{Fore.RED}[!] Found {len(self.results)} vulnerabilities:")
            for vuln in self.results:
                print(f"\n  Type: {vuln['type']}")
                print(f"  Payload: {vuln['payload']}")
                print(f"  Evidence: {vuln['evidence']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python scanner.py <url>")
        print(f"{Fore.YELLOW}Example: python scanner.py 'https://example.com/page?q=test'")
        sys.exit(1)

    target = sys.argv[1]
    scanner = SecurityScanner(target)
    scanner.run()
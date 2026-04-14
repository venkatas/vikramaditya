# Vikramaditya Enhanced - HAR-Based VAPT Platform

## Overview

Vikramaditya Enhanced now supports HAR (HTTP Archive) files for comprehensive authenticated vulnerability assessment and penetration testing (VAPT). This enhancement allows security professionals to perform in-depth testing using captured session data from legitimate user interactions.

---

## 🔥 Key Features

### **HAR File Support**
- **Automatic session extraction** from HAR files
- **Authentication token detection** (Bearer, API keys, cookies)
- **Endpoint discovery** with parameter analysis
- **Attack surface mapping** with vulnerability indicators

### **Comprehensive Testing**
- **SQL Injection** testing with multiple payload types
- **File Upload RCE** testing with bypass techniques
- **Authentication Bypass** testing
- **IDOR (Insecure Direct Object Reference)** testing
- **XSS (Cross-Site Scripting)** testing
- **Session Management** security analysis

### **Intelligent Analysis**
- **Technology stack detection** from response headers and paths
- **High-value target identification** (admin panels, file uploads, APIs)
- **Vulnerability prioritization** based on business impact
- **Automated remediation recommendations**

---

## 🚀 Quick Start

### **1. Basic HAR Analysis**
```bash
# Analyze HAR file and extract attack surface
python3 har_analyzer.py session_data.har
```

### **2. Interactive Enhanced VAPT**
```bash
# Start interactive mode with HAR support
python3 vikramaditya_enhanced.py --interactive
```

### **3. Direct HAR Testing**
```bash
# Process HAR file directly
python3 vikramaditya_enhanced.py /path/to/session.har
```

### **4. Command-line HAR Analysis**
```bash
# Specify HAR file via flag
python3 vikramaditya_enhanced.py --har session_data.har
```

---

## 📋 Complete Workflow

### **Step 1: Capture HAR File**
1. Open browser Developer Tools (F12)
2. Go to Network tab
3. Navigate through the target application
4. Perform authenticated actions (login, admin functions)
5. Right-click → Save as HAR file

### **Step 2: Run Analysis**
```bash
python3 har_analyzer.py captured_session.har
```

**Output:**
- `captured_session_analysis.json` - Complete analysis results
- Session tokens, cookies, and authentication data
- Discovered endpoints with vulnerability indicators
- Attack surface mapping

### **Step 3: Execute VAPT**
```bash
python3 vikramaditya_enhanced.py captured_session.har
```

**Automated Testing Includes:**
- ✅ SQL injection across all vulnerable parameters
- ✅ File upload RCE testing with multiple bypass techniques
- ✅ Authentication bypass on admin endpoints
- ✅ IDOR testing for user enumeration
- ✅ XSS testing across input parameters
- ✅ Session management security analysis

### **Step 4: Review Results**
```bash
# Results saved to timestamped JSON file
cat har_vapt_target.domain_YYYYMMDD_HHMMSS.json

# Generate HTML report
python3 reporter.py har_vapt_results.json --client "Target Organization"
```

---

## 🛠️ Advanced Usage

### **Multi-HAR Analysis**
```python
# Process multiple HAR files for comprehensive coverage
from har_analyzer import HARAnalyzer
from har_vapt_engine import HARVAPTEngine

har_files = ['session1.har', 'session2.har', 'admin_session.har']
combined_analysis = {}

for har_file in har_files:
    analyzer = HARAnalyzer(har_file)
    analysis = analyzer.analyze()
    # Merge analysis results
    combined_analysis.update(analysis)
```

### **Custom Vulnerability Testing**
```python
from har_vapt_engine import HARVAPTEngine

# Load analysis and create custom test
with open('session_analysis.json') as f:
    analysis = json.load(f)

engine = HARVAPTEngine(analysis)

# Run specific tests
sql_results = engine.test_sql_injection()
upload_results = engine.test_file_upload_rce()
auth_results = engine.test_authentication_bypass()
```

### **Integration with Existing Tools**
```bash
# Use with traditional infrastructure testing
python3 vikramaditya_enhanced.py domain.com     # Infrastructure VAPT
python3 vikramaditya_enhanced.py session.har    # Authenticated VAPT

# Combined approach for comprehensive assessment
python3 hunt.py --target domain.com             # Infrastructure
python3 vikramaditya_enhanced.py --har session.har  # Authenticated
```

---

## 📊 Output Analysis

### **HAR Analysis Output**
```json
{
  "session_data": {
    "cookies": {"session_id": "abc123", "auth": "token"},
    "bearer_tokens": ["eyJ0eXAiOiJKV1..."],
    "headers": {"Authorization": "Bearer ..."}
  },
  "endpoints": [
    {
      "url": "https://target.com/admin/users",
      "method": "GET",
      "vulnerability_indicators": ["admin_endpoint", "sqli_param"]
    }
  ],
  "attack_surface": {
    "high_value_targets": [...],
    "file_uploads": [...],
    "admin_endpoints": [...]
  }
}
```

### **VAPT Results Output**
```json
{
  "vulnerability_summary": {
    "total_vulnerabilities": 16,
    "critical": 6,
    "high": 4,
    "medium": 6
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "endpoint": "https://target.com/login.cgi",
      "severity": "critical",
      "details": "Authentication bypass via OR injection"
    }
  ],
  "recommendations": [
    "Implement parameterized queries",
    "Add input validation",
    "Fix authentication controls"
  ]
}
```

---

## 🎯 Vulnerability Detection Capabilities

### **SQL Injection**
- **Authentication bypass** via login forms
- **Parameter injection** in GET/POST parameters
- **Error-based detection** via SQL error messages
- **Time-based detection** using delay functions
- **Union-based detection** via response size analysis

### **File Upload RCE**
- **PHP shell upload** testing
- **PHTML bypass** techniques
- **Double extension** bypass (.php.jpg)
- **MIME type spoofing** detection
- **Content filtering** bypass attempts

### **Authentication Controls**
- **Admin endpoint** access without authentication
- **Session token validation** weakness testing
- **Privilege escalation** via parameter manipulation
- **Session hijacking** vulnerability assessment

### **IDOR (Insecure Direct Object Reference)**
- **User enumeration** via response size analysis
- **Directory traversal** attempts
- **Numerical ID** enumeration patterns
- **Unauthorized data access** testing

---

## 🔧 Configuration Options

### **Session Configuration**
```python
# Customize session handling
engine = HARVAPTEngine(analysis)
engine.session.timeout = 60  # Custom timeout
engine.session.headers.update({'X-Custom': 'Header'})  # Additional headers
```

### **Test Customization**
```python
# Customize SQL injection payloads
custom_payloads = [
    "' OR '1'='1'--",
    "'; DROP TABLE users--",
    "' UNION SELECT password FROM admin--"
]

# Custom file upload tests
custom_files = {
    'exploit.php': {'content': '<?php system($_GET["c"]); ?>', 'mime': 'text/plain'}
}
```

---

## 📈 Integration Examples

### **CI/CD Pipeline Integration**
```yaml
# GitHub Actions example
- name: HAR-based Security Testing
  run: |
    python3 har_analyzer.py tests/session.har
    python3 vikramaditya_enhanced.py tests/session.har
    python3 reporter.py vapt_results.json --output security_report.html
```

### **Automated Testing Script**
```bash
#!/bin/bash
# Comprehensive VAPT workflow

# Step 1: Infrastructure testing
python3 hunt.py --target $TARGET_DOMAIN

# Step 2: HAR-based authenticated testing
python3 vikramaditya_enhanced.py --har $HAR_FILE

# Step 3: Generate reports
python3 reporter.py vapt_results_*.json --client "$CLIENT_NAME"

echo "VAPT assessment completed successfully!"
```

---

## 🛡️ Security Considerations

### **Authorized Testing Only**
- ✅ **Only test systems you own or have written permission to test**
- ✅ **Ensure HAR files don't contain sensitive data before sharing**
- ✅ **Use test credentials, not production credentials**
- ✅ **Implement scope restrictions to prevent testing outside authorized targets**

### **Data Protection**
- 🔒 **HAR files may contain session tokens and sensitive data**
- 🔒 **Store HAR files securely and delete after testing**
- 🔒 **Don't commit HAR files to version control**
- 🔒 **Use dedicated test environments when possible**

---

## 📚 Examples and Use Cases

### **Enterprise Web Application Testing**
```bash
# Capture admin session
# Navigate: Login → Admin Panel → User Management → Reports
# Save as admin_session.har

python3 vikramaditya_enhanced.py admin_session.har
# Finds: Admin bypass, SQL injection in user search, file upload RCE
```

### **API Security Assessment**
```bash
# Capture API interactions via browser or Postman
# Include authentication flows and sensitive operations
# Save as api_session.har

python3 har_analyzer.py api_session.har
python3 har_vapt_engine.py api_session_analysis.json
# Tests: API authentication, parameter injection, data access controls
```

### **Multi-Tier Application Testing**
```bash
# Capture sessions for different user roles
python3 vikramaditya_enhanced.py user_session.har      # Regular user
python3 vikramaditya_enhanced.py admin_session.har     # Admin user
python3 vikramaditya_enhanced.py api_session.har       # API interactions

# Comprehensive privilege escalation and access control testing
```

---

## 🎉 Success Stories

### **Real-World Findings**
- **16 vulnerabilities** discovered in email platform testing
- **Critical SQL injection** authentication bypass detected
- **File upload RCE** with multiple bypass techniques confirmed
- **Admin panel access** without authentication identified
- **Complete session management** weaknesses documented

### **Remediation Verification**
```bash
# Before fixes
python3 vikramaditya_enhanced.py --har before_session.har
# Result: 16 vulnerabilities found

# After fixes
python3 vikramaditya_enhanced.py --har after_session.har
# Result: 0 vulnerabilities found - all issues remediated
```

---

## 📞 Support and Documentation

### **Getting Help**
- 📖 Review the comprehensive examples in `demo_har_vapt.py`
- 🔍 Check analysis output in `*_analysis.json` files
- 📊 Review detailed findings in VAPT result files
- 🐛 Report issues via GitHub repository

### **Advanced Configuration**
- 🔧 Customize payload lists in `har_vapt_engine.py`
- 🎯 Modify vulnerability detection logic
- 📈 Integrate with external tools and reporting systems
- 🔄 Implement custom workflow automation

---

**Vikramaditya Enhanced - Transforming VAPT with HAR-powered authenticated testing** 🚀
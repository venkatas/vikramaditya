"""bfla_scanner — forced-browsing / Broken Function-Level Authorization detector.

Closes a critical broken-authorization class: a low-privilege session (e.g. the form-login MAKER,
no SSO/admin role) reached admin/approver pages — /AdminQueue, /RecordDetails,
/FeeRecordDetails — that returned 200 instead of 403/SSO-redirect.

Detection (per codex+grok review): forced-browse a wordlist of admin/privileged paths
with a LOW-privilege session and flag *meaningful access* — not a bare 200. A finding is
CONFIRMED by DIFFERENTIAL: the low-priv session reaches the page (200, real content, not
a login render) while an UNAUTHENTICATED request to the same path is gated
(login/SSO redirect, 401/403, or 404). That proves the page is auth-gated but NOT
role-gated => function-level authorization is missing.

Iteration-2 backlog: discover paths from the crawl/site-map + JS (not just the wordlist);
compare low-priv vs admin rendering (titles/forms/action-buttons) to grade Critical when
state-changing controls are present; per-engagement wordlist extensions.
"""

DEFAULT_ADMIN_PATHS = [
    "/Admin", "/Admin.aspx", "/AdminPanel", "/AdminPanel.aspx", "/Administration",
    "/UserMaster", "/UserMaster.aspx", "/RoleMaster", "/RoleMaster.aspx",
    "/UserManagement", "/ManageUsers", "/Users", "/ManageRoles", "/Permissions",
    "/Reports", "/Reports.aspx", "/Report", "/Export", "/ExportToExcel",
    "/Settings", "/Configuration", "/Config",
    "/Approval", "/ApproveRequest", "/AdminQueue", "/AdminQueue.aspx",
    "/Dashboard", "/MasterData", "/Masters", "/Audit", "/AuditLog", "/Logs",
    "/EditUser",
]

# tokens in a response BODY that mean "this 200 is actually a login page", not real access
_LOGIN_BODY = (
    'type="password"', "txtpassword", 'name="password"', "j_password",
    "login.microsoftonline", "signin-oidc", "loginform",
)
# tokens in a redirect LOCATION that mean "gated" (sent to auth / landing)
_AUTH_REDIRECT = (
    "login", "signin", "sso", "oauth", "authorize", "microsoftonline",
    "adfs", "okta", "/home", "/default", "/account",
)


def _norm(r):
    """Tolerate get_fn returning (status, body) or (status, body, location)."""
    return (r[0], r[1], r[2] if len(r) > 2 else "")


def classify(status, body="", location=""):
    """Coarse access classification of a single response."""
    b = (body or "").lower()
    loc = (location or "").lower()
    if status in (401, 403):
        return "gated"
    if status == 404:
        return "absent"
    if status in (301, 302, 303, 307):
        return "gated" if any(m in loc for m in _AUTH_REDIRECT) else "redirect"
    if status == 200:
        if any(m in b for m in _LOGIN_BODY):
            return "gated"
        return "accessible"
    if status >= 500:
        return "error"
    return "other"


def scan(get_fn, paths=None, unauth_get=None):
    """Forced-browse `paths` (default: admin wordlist) with a low-privilege session.

    get_fn(path) / unauth_get(path) -> (status:int, body:str, location:str).
    Returns a list of BFLA findings. With an `unauth_get` baseline, a hit where low-priv
    is 'accessible' and unauth is gated/absent is CONFIRMED (high); without a baseline it
    is a CANDIDATE (medium) needing role-intent confirmation. Pages also reachable
    unauthenticated are treated as public and skipped.
    """
    paths = list(paths) if paths is not None else list(DEFAULT_ADMIN_PATHS)
    findings = []
    for path in paths:
        status, body, location = _norm(get_fn(path))
        if classify(status, body, location) != "accessible":
            continue
        confidence, severity = "candidate", "medium"
        if unauth_get is not None:
            us, ub, ul = _norm(unauth_get(path))
            if classify(us, ub, ul) in ("gated", "absent"):
                confidence, severity = "confirmed", "high"
            else:
                # reachable unauthenticated too -> public page, not a privilege boundary
                continue
        findings.append({
            "type": "broken_function_level_authorization",
            "path": path,
            "status": status,
            "severity": severity,
            "confidence": confidence,
            "evidence": (
                f"low-privilege session received HTTP {status} with content at {path}"
                + (" while an unauthenticated request is gated — the page is auth-gated "
                   "but NOT role-gated (forced-browsing / BFLA)"
                   if confidence == "confirmed"
                   else " (no unauthenticated baseline supplied — confirm the path is "
                        "intended for a higher-privilege role)")
            ),
        })
    return findings

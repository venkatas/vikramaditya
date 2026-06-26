"""hunt._parse_sqlmap_confirmation — must NOT confirm a sqlmap FALSE POSITIVE.

Live anti-fabrication regression (an authenticated ASP.NET WebForms engagement): sqlmap printed a transient
"appears to be ... injectable" + "it looks like the back-end DBMS is 'MySQL'" during
false-positive fingerprinting, then REJECTED it ("false positive or unexploitable" /
"does not seem to be injectable" / "all tested parameters do not appear to be injectable").
The parser confirmed on the "back-end dbms is" substring and hunt.py wrote a fabricated
INJECTABLE_PARAMS.txt (DBMS unknown, params n/a). A confirmation MUST require the real
structural injection block, and an explicit not-injectable verdict MUST veto it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402

FALSE_POSITIVE = """
[INFO] (custom) POST parameter '#1*' appears to be 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[INFO] checking if the injection point on (custom) POST parameter '#1*' is a false positive
[WARNING] false positive or unexploitable injection point detected
[WARNING] (custom) POST parameter '#1*' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable.
"""

REAL = """
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
"""


def test_false_positive_is_not_confirmed():
    conf = hunt._parse_sqlmap_confirmation(FALSE_POSITIVE)
    assert conf["confirmed"] is False, "a sqlmap-rejected false positive must NOT be confirmed"


def test_real_injection_is_confirmed():
    conf = hunt._parse_sqlmap_confirmation(REAL)
    assert conf["confirmed"] is True
    assert any("id" in p for p in conf["params"])
    assert "MySQL" in conf["dbms"]


def test_dbms_fingerprint_guess_alone_does_not_confirm():
    # "it looks like the back-end DBMS is X" with no Parameter block + a negative verdict
    out = "it looks like the back-end DBMS is 'MySQL'.\n[WARNING] does not seem to be injectable\n"
    assert hunt._parse_sqlmap_confirmation(out)["confirmed"] is False


# ── --eval crash must be reported INCONCLUSIVE, not a clean negative (tool bug #2) ──
EVAL_CRASH = ("[12:35:44] [INFO] testing connection to the target URL\n"
              "[12:35:44] [CRITICAL] an error occurred while evaluating provided code "
              "('SyntaxError: invalid decimal literal')\n[*] ending @ 12:35:44")


def test_eval_crash_detected_as_inconclusive():
    assert hunt._sqlmap_eval_crashed(EVAL_CRASH) is True
    assert "invalid decimal literal" in hunt._sqlmap_eval_crash_reason(EVAL_CRASH)


def test_real_negative_is_not_an_eval_crash():
    out = ("[INFO] testing '...'\n[WARNING] POST parameter '#1*' does not seem to be injectable\n"
           "[CRITICAL] all tested parameters do not appear to be injectable.")
    assert hunt._sqlmap_eval_crashed(out) is False


def test_real_injection_is_not_an_eval_crash():
    out = "sqlmap identified the following injection point(s):\nParameter: id (GET)\n"
    assert hunt._sqlmap_eval_crashed(out) is False

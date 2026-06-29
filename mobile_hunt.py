#!/usr/bin/env python3
"""
mobile_hunt.py — Mobile (APK/IPA/AAB) VAPT engine (v9.6.0)

Wraps MobSF (static + dynamic + malware analysis), Frida (runtime
instrumentation), Objection (SSL pinning bypass / keychain dumps),
and Drozer (Android IPC attack surface) into a single Vikramaditya-
shaped session output.

Closes the longest-standing scope gap in the platform — every Indian
enterprise engagement asks "do you do mobile?" and we currently say no.

Output layout: findings/<app-id>/mobile/{static.json, dynamic.json,
frida_traces/, drozer_ipc.txt, mobsf_pdf_report.pdf}

Usage:
    python3 mobile_hunt.py --apk path/to/app.apk
    python3 mobile_hunt.py --ipa path/to/app.ipa --frida-pinning-bypass
    python3 mobile_hunt.py --apk app.apk --drozer  # Android IPC pass
    python3 mobile_hunt.py --apk app.apk --mobsf-url http://localhost:8000

Tool requirements (wrapper degrades silently if absent):
    MobSF      — `docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf`
                 then export MOBSF_API_KEY (visible in MobSF dashboard top-right)
    Frida      — `pip install frida-tools` + USB-connected device with frida-server running
    Objection  — `pip install objection`
    Drozer     — `pip install drozer-python3` + drozer-agent.apk on device
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent
DEFAULT_MOBSF = os.environ.get("MOBSF_URL", "http://127.0.0.1:8000")
MOBSF_KEY = os.environ.get("MOBSF_API_KEY", "")


def _which(name: str) -> str | None:
    return shutil.which(name)


def _post(url: str, data: dict, files: dict | None = None) -> dict:
    """Tiny urllib-based form POST so we don't add a `requests` dep."""
    import urllib.request
    import urllib.parse
    if files:
        # multipart upload — fall back to curl for simplicity.
        # Launch via procutil (os.posix_spawn) NOT raw subprocess.run: under the
        # vikramaditya orchestrator the process has already done in-process HTTPS,
        # loading Apple's Network.framework whose non-fork-safe pthread_atfork child
        # handler SIGSEGVs (rc=-11) any fork()+exec child on macOS. posix_spawn skips
        # atfork handlers. Matches the policy used by frida/objection/drozer below.
        cmd = ["curl", "-sS", "-X", "POST", url, "-H", f"Authorization: {MOBSF_KEY}"]
        for k, v in data.items():
            cmd += ["-F", f"{k}={v}"]
        for k, fp in files.items():
            cmd += ["-F", f"{k}=@{fp}"]
        import procutil
        try:
            res = procutil.run_capture(cmd, timeout=600, shell=False, merge_stderr=False)
        except Exception as e:
            return {"_error": f"upload child failed to launch: {e}"}
        out = (res.get("stdout") or "").strip()
        if res.get("timed_out"):
            return {"_error": "upload timed out"}
        if not out:
            # Empty stdout from a non-zero rc (or a crashed/killed child) must surface
            # as an error so mobsf_scan does not mistake it for a clean empty response.
            rc = res.get("returncode")
            return {"_error": f"upload child returned empty output (rc={rc})"}
        try:
            return json.loads(out)
        except Exception as e:
            return {"_error": f"upload response not JSON: {e}"}
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Authorization": MOBSF_KEY,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"_error": str(e)}


def mobsf_scan(app_path: str, mobsf_url: str, out_dir: Path) -> dict | None:
    """MobSF static analysis via REST API. Requires the server running and
    MOBSF_API_KEY env var. Returns the parsed JSON report."""
    if not MOBSF_KEY:
        print("[!] MOBSF_API_KEY env var not set — skipping MobSF static scan")
        print("    Start MobSF: docker run -d -p 8000:8000 opensecurity/mobile-security-framework-mobsf")
        print("    Then: export MOBSF_API_KEY=<key from http://localhost:8000>")
        return None
    print(f"[*] MobSF upload → {mobsf_url}")
    upload = _post(f"{mobsf_url}/api/v1/upload",
                   data={}, files={"file": app_path})
    if not upload or "_error" in upload:
        print(f"[!] MobSF upload failed: {upload.get('_error', upload)}")
        return None
    scan_hash = upload.get("hash") or upload.get("file_name")
    print(f"[*] MobSF scan started: hash={scan_hash}")
    _post(f"{mobsf_url}/api/v1/scan",
          data={"scan_type": upload.get("scan_type", "apk"),
                "file_name": upload.get("file_name", ""),
                "hash": scan_hash})
    print("[*] Waiting for scan completion (up to 5 min)...")
    last_report = None
    for _ in range(60):
        time.sleep(5)
        report = _post(f"{mobsf_url}/api/v1/report_json",
                       data={"hash": scan_hash})
        if report and "_error" not in report:
            last_report = report
            # Gate completion on a stable, version-independent core field rather than
            # the optional 'appsec' scorecard (added in newer MobSF, absent/empty for
            # some IPA/AAB reports) — keying on 'appsec' alone discards finished scans.
            if (report.get("appsec") or report.get("version")
                    or report.get("md5") or report.get("app_name")
                    or report.get("file_name")):
                (out_dir / "mobsf_static.json").write_text(json.dumps(report, indent=2, default=str))
                print(f"[+] MobSF report → {out_dir / 'mobsf_static.json'}")
                return report
    # On timeout, persist whatever non-empty report we last fetched rather than
    # silently dropping a near-complete scan.
    if last_report:
        (out_dir / "mobsf_static.json").write_text(json.dumps(last_report, indent=2, default=str))
        print(f"[!] MobSF scan did not signal completion; persisted last partial report "
              f"→ {out_dir / 'mobsf_static.json'}")
        return last_report
    print("[!] MobSF scan timed out")
    return None


def frida_pinning_bypass(app_id: str, out_dir: Path) -> str | None:
    """Run frida-trace with the universal pinning-bypass script. Requires
    a USB-connected device or emulator running frida-server."""
    if not _which("frida"):
        print("[!] frida CLI not found — pip install frida-tools")
        return None
    out_log = out_dir / "frida_pinning.log"
    # Universal Android SSL pinning bypass (compact form)
    script = """
    Java.perform(function() {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.vikramaditya.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom').implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
        };
        console.log('[+] SSL pinning bypassed for ' + Java.use('android.app.ActivityThread')
                    .currentApplication().getPackageName());
    });
    """
    # Launch via procutil (os.posix_spawn): the MobSF phase runs urllib.urlopen
    # (in-process HTTPS) before this, loading Apple's Network.framework whose
    # non-fork-safe pthread_atfork child handler SIGSEGVs (rc=-11) any fork()+exec
    # child on macOS. posix_spawn skips atfork handlers. procutil has no stdin-input
    # channel, so the JS script is written to a temp file and passed via `frida -l`.
    import procutil
    script_path = out_dir / "frida_pinning_bypass.js"
    try:
        script_path.write_text(script)
        cmd = ["frida", "-U", "-l", str(script_path), "-f", app_id, "--no-pause"]
        res = procutil.run_capture(cmd, timeout=30, shell=False, merge_stderr=True)
        out_log.write_text(res["stdout"] or "")
        if res["returncode"] not in (0, None) and not res["timed_out"]:
            print(f"[!] frida exited rc={res['returncode']} — possible crashed child")
        print(f"[+] Frida pinning-bypass attempted → {out_log}")
        return str(out_log)
    except Exception as e:
        print(f"[!] frida failed: {e}")
        return None


def objection_keychain(app_id: str, out_dir: Path) -> str | None:
    """Objection iOS keychain dump (iOS only)."""
    if not _which("objection"):
        print("[!] objection not found — pip install objection")
        return None
    out_log = out_dir / "objection_keychain.txt"
    cmd = ["objection", "-g", app_id, "explore",
           "-c", "ios keychain dump",
           "-q"]
    # posix_spawn launch — runs after the MobSF urllib HTTPS phase loaded Apple's
    # Network.framework; a raw fork()+exec would SIGSEGV (rc=-11) on macOS.
    import procutil
    try:
        res = procutil.run_capture(cmd, timeout=60, shell=False, merge_stderr=True)
        out_log.write_text(res["stdout"] or "")
        if res["returncode"] not in (0, None) and not res["timed_out"]:
            print(f"[!] objection exited rc={res['returncode']} — possible crashed child")
        print(f"[+] Objection keychain dump → {out_log}")
        return str(out_log)
    except Exception as e:
        print(f"[!] objection failed: {e}")
        return None


def drozer_ipc(app_id: str, out_dir: Path) -> str | None:
    """Drozer Android IPC attack surface enumeration."""
    if not _which("drozer"):
        print("[!] drozer not found — pip install drozer-python3 + drozer-agent.apk")
        return None
    out_log = out_dir / "drozer_ipc.txt"
    commands = [
        f"run app.package.attacksurface {app_id}",
        f"run app.activity.info -a {app_id}",
        f"run app.provider.info -a {app_id}",
        f"run app.broadcast.info -a {app_id}",
        f"run app.service.info -a {app_id}",
    ]
    # posix_spawn launch — runs after the MobSF urllib HTTPS phase loaded Apple's
    # Network.framework; a raw fork()+exec would SIGSEGV (rc=-11) on macOS.
    import procutil
    try:
        with open(out_log, "w") as fh:
            for c in commands:
                fh.write(f"\n## {c}\n")
                res = procutil.run_capture(["drozer", "console", "connect", "-c", c],
                                           timeout=60, shell=False, merge_stderr=True)
                fh.write(res["stdout"] or "")
                if res["returncode"] not in (0, None) and not res["timed_out"]:
                    print(f"[!] drozer exited rc={res['returncode']} on '{c}' — possible crashed child")
        print(f"[+] Drozer IPC → {out_log}")
        return str(out_log)
    except Exception as e:
        print(f"[!] drozer failed: {e}")
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mobile_hunt",
                                 description="Vikramaditya mobile (APK/IPA) VAPT")
    ap.add_argument("--apk", help="Path to .apk")
    ap.add_argument("--ipa", help="Path to .ipa")
    ap.add_argument("--aab", help="Path to .aab")
    ap.add_argument("--app-id", help="Bundle/package ID for runtime tests")
    ap.add_argument("--mobsf-url", default=DEFAULT_MOBSF)
    ap.add_argument("--frida-pinning-bypass", action="store_true")
    ap.add_argument("--objection-keychain", action="store_true")
    ap.add_argument("--drozer", action="store_true")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    app_path = args.apk or args.ipa or args.aab
    if not app_path and not args.app_id:
        ap.error("provide --apk / --ipa / --aab or --app-id for runtime tests")

    label = (args.app_id or Path(app_path or "mobile").stem).replace("/", "_")
    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "mobile"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Mobile VAPT — output: {out_dir}")
    print(f"[*] Started: {datetime.now().isoformat(timespec='seconds')}")

    mobsf_status = "not_run"
    if app_path:
        mobsf_report = mobsf_scan(app_path, args.mobsf_url, out_dir)
        mobsf_status = "ok" if mobsf_report else "degraded"
    if args.app_id and args.frida_pinning_bypass:
        frida_pinning_bypass(args.app_id, out_dir)
    if args.app_id and args.objection_keychain:
        objection_keychain(args.app_id, out_dir)
    if args.app_id and args.drozer:
        drozer_ipc(args.app_id, out_dir)

    summary = {
        "tool": "vikramaditya.mobile_hunt",
        "version": "9.6.0",
        "app_path": app_path,
        "app_id": args.app_id,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
        "artifacts": [str(p) for p in out_dir.iterdir() if p.is_file()],
        # Per-phase status so a consumer of summary.json can distinguish
        # "MobSF ran and found nothing" from "MobSF never ran / failed / timed out".
        "phases": {"mobsf_static": mobsf_status},
        "degraded": mobsf_status == "degraded",
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    if mobsf_status == "degraded":
        print("[!] mobsf_static phase degraded — core static analysis did not complete")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

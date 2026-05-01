# Vikramaditya v8.0 → v9.0 Backlog — Engagement-driven gaps

Filed 2026-05-01, after a four-day live engagement (29 Apr – 1 May) against
two AWS accounts and 7 client domains. Every item below is anchored to a
specific finding the tool either *missed*, *false-positived*, or *required
manual extraction* on. Priority is impact-on-engagement-quality, highest first.

The earlier 2026-04-29 backlog (P0–P9) is still open in parallel — the items
here are *additive* and engagement-validated.

---

## P10 — JS endpoint mining for SPA / Next.js / Vite apps

**Problem.** `recon.sh` Phase 5 runs `LinkFinder.py` on top-level JS files but
does not (a) recursively download referenced `_next/static/chunks/*.js`,
(b) expand minified-string-table extraction, or (c) emit endpoints scoped to
the site's own backend hosts.

**Engagement evidence.** The UNI5 HRMS app at `15.207.251.19/signin` is a
Next.js application. Its JS chunks reveal **two in-scope subdomains** that no
passive subdomain source surfaced:

- `hrms-organisation-gateway.adfactorspr.com`
- `hrms-user-gateway.adfactorspr.com`

Both are real backend gateways. `subfinder + amass + assetfinder + bbot
subdomain-enum` produced 0 results for either. The only way to find them was
to grep the Next.js bundle (`/_next/static/chunks/app/(auth)/signin/page-*.js`).

**What to add.**

1. New module `recon/js_extractor.py` (or wrap `xnLinkFinder` —
   <https://github.com/xnl-h4ck3r/xnLinkFinder>):
   - Recursively walk `_next/static/chunks/*.js`, Vite `assets/index-*.js`,
     React Router `static/js/*.chunk.js`, Angular `main.*.js`.
   - Extract every absolute URL, relative endpoint, fetch/axios/RTKQuery call.
   - De-duplicate, cluster by host, emit per-host endpoint files.
2. Cross-feed any newly-discovered hosts back into `recon.sh` as additional
   subdomain seeds before httpx probing.
3. Detect the API base from `process.env.NEXT_PUBLIC_*`, Vite `__VITE_*`,
   Angular `environment.ts`-style emitted constants.

**Acceptance.** A second engagement against any Next.js / React / Vite app
must surface backend API hosts that subdomain enum misses.

---

## P11 — TLS Subject-Alternative-Name harvesting

**Problem.** `recon.sh` does not extract cert SANs. ProjectDiscovery `tlsx`
is now installed manually and was the tool that surfaced the new client
domain `merryspiders.com` and the subdomain `kalki-dashboards` during the
engagement. Without tlsx these would have been missed entirely.

**Engagement evidence.** Running `tlsx -san -cn` against the cloud-known IP
list produced (after deduping):

```
adfactorspr.com
cloudfront.net
crawler-testing.pranapr.com
kalki-dashboards         ← new
merryspiders.com         ← new — third client domain
pranapr.com
radar-edition-testing.pranapr.com
```

**What to add.**

1. Add a `Phase 1.5: TLS Cert SAN Harvest` to `recon.sh` after live-host
   discovery: `cat live/ips.txt | tlsx -san -cn -resp-only -silent | sort -u
   > certs/sans.txt`.
2. Feed back into the subdomain pipeline before httpx — so any cert-leaked
   subdomain still gets active-scanned in the same run.
3. For whitebox: pull cert SANs from the `cloudfront list-distributions`
   `ViewerCertificate.IamCertificateId` and any uploaded ACM certs as part
   of the cloud asset feed.

**Acceptance.** SAN harvest must run on every recon and emit a delta vs. the
existing subdomain list. Goal is "no related domain owned by the org should
be missing from the engagement footprint."

---

## P12 — Greybox correlator (whitebox → blackbox feed)

**Problem.** The `whitebox/correlator/` package today does
asset_feed_*.json output and PMapper privesc-chain merging. It does NOT
yet feed the inventory back into the blackbox engine. During the engagement
this was done manually with `/tmp/greybox_seed.py` and
`/tmp/greybox_enrichment.py`.

**Engagement evidence.** Cloud inventory contained 81 public IPs. Pure
blackbox DNS recon found 11. The 70-IP delta included:
- Kalki.ai UAT (3.109.133.130) — undisclosed staging environment
- GLPI ticketing system (13.204.9.189) — known-CVE software
- 4× IIS 10.0 default-install pages on production hosts
- Apache default install page on `AD-Factor-Erp-Web-2`
- OpenVPN-AS portals × 2

None of these would have surfaced from blackbox alone.

**What to add.**

1. New module `whitebox/correlator/greybox_seed.py`:
   - Read `inventory/ec2/*.json` → public IPs + public DNS names
   - Read `inventory/elbv2/*.json` → Internet-facing LB DNS
   - Read `inventory/cloudfront/global.json` → distribution domain names + aliases
   - Read `inventory/route53/global.json` → all hosted zones (potential client domains)
   - Emit `correlation/greybox_seed.json` consumable by `recon.sh` /
     `scanner.sh` / `vikramaditya.py`.
2. Update `recon.sh` to accept a `--greybox-seed` flag that pre-populates
   the `live/ips.txt` and `subdomains/all.txt` before active probing.
3. Update `scanner.sh` to skip-fingerprint hosts already known from the
   greybox seed (faster), but full-scan them anyway.

**Acceptance.** Running `cloud_hunt` on a target's AWS account followed by
`vikramaditya.py target.com` must automatically expose every public IP
visible to the cloud inventory through the blackbox scanner phases. Manual
`grep | tlsx | dnsx` chains gone.

---

## P13 — Email security audit module

**Problem.** Email security findings (DMARC, SPF, DKIM, MTA-STS, TLS-RPT,
DNSSEC) are entirely manual today — `dig +short TXT _dmarc.<domain>` etc.
The earlier `email_audit/` per-check package referenced in CLAUDE.md does
not actually exist as an automated end-to-end module.

**Engagement evidence.** Both client domains had email-security gaps that
became headline findings:

- `pranapr.com`: DMARC missing entirely → freely spoofable
- `pranapr.com`: DKIM not visible at any common selector
- Both: MTA-STS, TLS-RPT, DNSSEC missing

**What to add.**

`whitebox/email/audit.py` (or symmetric blackbox `email_audit.py`):
1. SPF lookup + parse `~all` vs `-all`, count `include:` (10-DNS-lookup
   limit warning), flag `+all` immediately.
2. DMARC presence + `p=none/quarantine/reject`, `sp=`, `pct=`, `ruf=`,
   `rua=` analysis.
3. DKIM common-selector probe (>20 selectors) + reportable list of which
   selectors exist.
4. MTA-STS DNS + policy-file fetch from
   `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
5. TLS-RPT TXT lookup at `_smtp._tls.<domain>`.
6. DNSSEC chain validation (DS at parent, DNSKEY at zone).
7. MX existence + reverse PTR + open-relay test (only if --aggressive).

Output: a per-domain JSON report + Markdown section ready for the
report-generator.

**Acceptance.** A run of `vikramaditya.py example.com` must auto-include
an "Email Security" chapter in the final report without any manual `dig`.

---

## P14 — Reachability verification on every exposure finding (already P0)

Tracked separately as P0 in the 2026-04-29 backlog. Cross-referencing here
because **today's engagement re-verified its importance**:

- The MongoDB regression (29 Apr OPEN → 30 Apr FILTERED → 1 May OPEN AGAIN)
  was caught only by manual re-verification, not by the tool's own logic.
- The 4 of 5 "MSSQL 1433 from 0/0" SGs in adf-pranapr (orphan rules with
  no instances) would have shipped as "5 critical exposures" without
  reachability gating. Real exploitable count was 0.
- The kalki.pranapr.com SPA-catchall would have shipped 36 false-positive
  "exposed config files" (already P0 / discussed in 29-Apr backlog).

**No new sub-items beyond what's already filed.** Just confirming P0 is
the highest-leverage fix in the entire backlog.

---

## P15 — Visual recon module (gowitness integration)

**Problem.** No automated screenshot phase in `recon.sh` today. During the
engagement, `gowitness` ran ad-hoc and surfaced an immediate correction:
`15.207.251.19:443` was reported as "Apache default install page" in v1.3
of the AWS-team report. Screenshots showed it's actually the **UNI5 HRMS
production Sign In page** — completely different finding (PII / payroll
target, not abandoned host).

**What to add.**

1. New `recon.sh` Phase: `Phase 4.5: Visual recon`
   - Run `gowitness scan file -f live/urls.txt -t 8 --write-jsonl`
   - Emit `live/screenshots/*.jpeg` + `live/visual.jsonl`
2. Reporter integration:
   - Each "live host" row in the HTML report includes the screenshot inline.
   - Auto-detect default-install pages (IIS, Apache, Nginx defaults) by
     matching screenshot title/server-banner combinations and flag them.
3. CV / hash-based dedup so 4 identical IIS-default screenshots only
   render once with a "+ 3 similar" link.

**Acceptance.** Engagement reports surface "title in browser" not just
"HTTP 200" — operator can spot a forgotten admin panel in 30 seconds of
scrolling.

---

## P16 — MongoDB / Redis / DB-protocol probe library

**Problem.** `scanner.sh` has Check 1-12 covering web vuln classes but no
"is this Internet-exposed DB protocol pre-auth-responsive?" check. Today
this was done manually for the MongoDB Headline 1 finding (raw socket +
OP_MSG hello).

**Engagement evidence.** MongoDB on 13.202.242.247:27017 — pre-auth wire
protocol responded with `InvalidBSON` error to a malformed `OP_MSG`,
confirming auth state. Then `listDatabases` was rejected with
`Unauthorized`, allowing downgrade from "data extractable" to "auth
enforced but exposure still inappropriate." This nuance came from manual
protocol crafting; the tool has no equivalent automation.

**What to add.**

`scanner/db_proto_probe.py`:

| DB | Pre-auth probe | Auth-required canary |
|:--|:--|:--|
| MongoDB 27017 | OP_MSG hello | listDatabases admin-cmd |
| Redis 6379 | INFO server | CONFIG GET dir |
| MySQL 3306 | handshake greeting | login attempt as `root` |
| PostgreSQL 5432 | startup-message reply | login as `postgres` |
| Elasticsearch 9200/9300 | `/` GET | `/_cluster/state` |
| ClickHouse 8123/9000 | ping | `/query?query=SELECT 1` |
| Memcached 11211 | `version` | `stats` |
| Cassandra 9042 | OPTIONS frame | STARTUP |
| MS SQL 1433 | TDS pre-login | TDS login |

Output: per-finding JSON with `protocol_responsive`, `auth_enforced`,
`server_version`, `recommended_action`.

**Acceptance.** Open DB ports auto-distinguish "filtered", "open with
auth", "open without auth" — three-tier severity instead of one.

---

## P17 — bbot wrapper as recon-engine alternative

**Problem.** `recon.sh` chains a fixed pipeline (`subfinder` → `amass` →
`dnsx` → `httpx` → `katana` → ...). `bbot` (ProjectDiscovery alternative)
runs the same in a single command with more sources, deeper graph, and
auto-discovery of cloud assets / repos / certs.

**Engagement evidence.** Today's bbot install hit a sudo-prompt issue on
macOS Python 3.14 (`bbot.cli._main` → `helpers.depsinstaller.install`
asks for sudo to install core deps). Need to either (a) ship bbot in a
managed Python 3.11 venv with `--allow-deps` pre-set, or (b) call bbot
modules directly via its Python API to avoid the sudo path.

**What to add.**

`recon_bbot.py` — wrapper that:
1. Spawns bbot with `-p subdomain-enum,web-basic,cloud-enum` against
   the target.
2. Maps bbot's NDJSON event stream into the existing `recon/<target>/`
   directory layout.
3. Falls back to native `recon.sh` if bbot is unavailable.

**Acceptance.** `vikramaditya.py target.com --recon-engine bbot` runs an
end-to-end engagement using bbot's superset-of-sources pipeline.

---

## P18 — Public S3 bucket-policy capture in findings

**Problem.** When Prowler emits `s3_bucket_public_access` Critical, the
finding's `description` says "Ensure no S3 buckets open to Everyone or
Any AWS user." The actual bucket policy that makes it public is NOT
captured in the finding. During this engagement, the AWS team needed the
verbatim policy quote (`{"Sid":"AllowPublicReadAccessToAllObjects",
"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}`) for their
remediation; we hand-fetched it via `s3api get-bucket-policy`.

**What to add.**

In `whitebox/audit/normalizer.py`, when normalizing a
`s3_bucket_public_access` Prowler finding, also capture:
- `BucketPolicy` (verbatim JSON)
- `BucketPolicyStatus.IsPublic` (boolean)
- `BlockPublicAccess` (4-tuple)
- `BucketAcl` (Grants list)

Render in the report's evidence section so the AWS team has the
copy-paste-ready facts.

**Acceptance.** `findings.json` for any Critical/High S3 finding is
self-contained — no manual `aws s3api get-*` follow-ups needed for the
report.

---

## P19 — UI / SPA catchall fingerprint suppression in exposure module

**Problem.** Already filed implicitly in P0/Headline 4 of the v1.0 report
withdrawal. Logged here as a discrete fix: `recon.sh` Phase 9 (Exposed
Config Files) writes paths-with-200 directly to `exposure/config_files.txt`
without consulting the catchall fingerprint that `scanner.sh` Check 0
already detects (and logs as `Catchall-200 detected`).

**Engagement evidence.** kalki.pranapr.com — 36 false-positive paths
(every path returns the same 2028 B SPA shell HTML, md5
`501e602072329a3721263be5d6401292`).

**What to add.**

1. Lift `scanner.sh`'s catchall-detection into a shared
   `recon/lib/catchall.sh`.
2. Source it from Phase 9.
3. Compute md5 of each successful 200 response and compare to the host's
   per-shape catchall fingerprint before writing to
   `exposure/config_files.txt`.

**Acceptance.** A re-run against kalki.pranapr.com produces 0 entries in
`exposure/config_files.txt`, not 36.

---

## P20 — wpscan via Docker fallback

**Problem.** Homebrew `wpscan@3.8.28` on macOS has a Bundler / Ruby gem-path
mismatch; today's run failed with
`bundler-4.0.6/exe/bundle:16:in '<main>'` errors on every WP host.
`nuclei -tags wordpress` ran clean as a fallback but does not enumerate
plugins / themes / users the way wpscan does.

**What to add.**

`scanner/wpscan_docker.sh`:
```bash
docker run --rm -v "$PWD/output:/output" wpscanteam/wpscan \
    --url "$1" --random-user-agent --no-update --format json \
    -o "/output/$(basename $1).json" \
    --enumerate vp,vt,u1-3 --plugins-detection mixed --disable-tls-checks
```

Wrap in `scanner.sh` Check 7 (CMS Detection) — fall back to docker image
when local wpscan binary is broken.

**Acceptance.** WP cluster (28 hosts on pranapr.com today) gets a clean
plugin / theme / user enumeration on every engagement run.

---

## P21 — External cloud bucket enumeration (cloud_enum integration)

**Problem.** `cloud_enum` is now installed at `~/tools/cloud_enum/` but is
not invoked by any Vikramaditya pipeline. It scans S3 / Azure Blob / GCP
storage from outside (no creds) — finds shadow IT and forgotten tenants
that don't appear in the IAM-visible inventory.

**Engagement evidence.** Yesterday's `whitebox.cloud_hunt` listed 57
buckets in `adf-pranapr` (heuristic-scanned 10 of them for secrets). External
`cloud_enum` would tell us whether there are buckets *outside* that
account also matching `adfactors*` / `pranapr*` / `merryspiders*` prefixes.

**What to add.**

`whitebox/external_cloud_enum.py`:
1. Take the engagement's domain + org list as input.
2. Run `cloud_enum` for each as a brand prefix.
3. Cross-reference with `inventory/s3/global.json` — any external bucket
   *not* in the IAM-visible set is a "shadow" finding worth investigating.

**Acceptance.** Engagement report contains a "Shadow IT" section listing
public-readable buckets matching the brand prefix that the audited AWS
account does not own.

---

## P22 — `Description` field round-trip in SG findings

**Problem.** During verification today the SG `sg-0e29ba05dae0a38bd`
inbound rule for tcp/27017 had `"Description": "Mongo DB"` — meaning the
operator who created it intentionally labelled it. The Prowler / cloud_hunt
finding currently does NOT capture this description.

**Engagement evidence.** Knowing the rule is intentional vs. accidental
materially changes the recommendation tone — when operator wrote
"Mongo DB" as the description, the message is "this was deliberate, here's
why it's still wrong" not "you may have forgotten this rule exists."

**What to add.**

In `whitebox/exposure/analyzer.py`, when emitting a SG-from-internet
finding, include the `Description` field from `IpPermissions[].IpRanges[]`
verbatim. Reporter renders it as a quoted string in the finding body.

**Acceptance.** Findings show "operator-intent string" inline so the
report's tone matches the apparent intent.

---

## P23 — `cloud_hunt` should auto-enroll domain seeds from Route 53

**Problem.** During the engagement, 5 client domains existed in adf-pranapr
Route 53 (ad-factors.com, adfactors-{dev,prod,uat}.com, plus indirectly
merryspiders.com via the `Adf-Prod-UI-merryspiders` ELB name) but the
original blackbox scope was just 2 domains (`adfactorspr.com`,
`pranapr.com`). The other 5 were discovered manually mid-engagement.

**What to add.**

When `cloud_hunt` runs against an account, it should emit a
`recon/<account>/scope-suggestion.json` listing every Route53 hosted zone,
every CloudFront alias, every ELB DNS, and every ACM cert SAN — labeled
"client owns this; consider adding to blackbox scope."

`vikramaditya.py` reads that file and prompts the operator: "5 additional
client domains found. Add to scope? [y/N]".

**Acceptance.** Operators do not miss "third-party client products living
in the same AWS account" simply because they were given a 2-domain scope
sheet at engagement kickoff.

---

## P24 — Memory of false-positive history

**Problem.** Across three days of the engagement, the same recon-tool
false positive (kalki SPA-catchall) was re-discovered three times. The
tool has no memory of prior false-positives; every re-run flags the same
36 paths.

**What to add.**

`whitebox/cache/false_positive_db.json`: per-host, per-finding-class
record of "verified false positive at YYYY-MM-DD." When an engagement
re-runs, the reporter consults this DB and either suppresses the finding
or flags it as "previously withdrawn — re-verify before re-stating."

**Acceptance.** Day-2 of an engagement does not re-publish day-1
false positives.

---

## Summary table

| # | Tag | Effort | Impact |
|:--|:----|:-------|:-------|
| P10 | JS endpoint mining | M (1-2 weeks) | High — hidden subdomains in modern SPAs |
| P11 | TLS SAN harvest | S (2-3 days) | High — found new client domain in this engagement |
| P12 | Greybox correlator (whitebox→blackbox) | M | High — 70 cloud-only IPs missed by blackbox today |
| P13 | Email security audit module | M | High — DMARC missing was top-3 finding |
| P14 | Reachability verification (already P0) | M | Highest — 60% Critical-rate overstatement without it |
| P15 | Visual recon (gowitness) | S | Medium — corrected the UNI5 finding |
| P16 | DB-protocol probe library | M | High — distinguish 3 severity tiers on DB ports |
| P17 | bbot wrapper | M | Medium — alternative recon source |
| P18 | S3 bucket-policy capture in findings | XS | Medium — saves manual follow-up |
| P19 | UI SPA catchall fp suppression | XS | High — 36 false positives per engagement |
| P20 | wpscan Docker fallback | XS | Medium — WP CVEs need wpscan, not just nuclei |
| P21 | External cloud_enum integration | S | Medium — shadow IT detection |
| P22 | SG rule `Description` round-trip | XS | Low — better report tone |
| P23 | Auto-enroll domain seeds from Route53 | S | High — caught 5 additional domains today |
| P24 | False-positive memory DB | S | Medium — saves re-discovery cost |

---

## Tooling that should ship with v9.0

Pre-installed (or auto-installed on first run via `pipx` / `go install`):

`bbot`, `tlsx`, `alterx`, `shuffledns`, `massdns`, `dnsgen`, `fingerprintx`,
`xnLinkFinder`, `noseyparker`, `cloud_enum`, `gowitness`, `subzy`, `subjack`,
`wpscan` (via Docker), plus the existing PD base.

Suggested CLAUDE.md addition documenting each tool's role and install path,
to match the existing `prowler-cloud==4.5.0` / `principalmapper>=1.1.5`
stanza.

# Whitebox VAPT — Post-Merge Backlog

Filed 2026-04-29 after live validation against `adf-pranapr` (account 591335425990)
and cross-check with the AdfactorPR AWS Posture report dated 29-Apr-2026.

The branch `feat/whitebox-vapt` is being merged with these gaps known and tracked.
None are bugs in shipped behavior; all are net-new detection surface.

Priority is severity-of-blind-spot, highest first.

---

## P0 — Reachability verification on every exposure finding

**Problem.** `whitebox/exposure/analyzer.py::is_public_to_internet` and Prowler's
`ec2_securitygroup_*` family flag a SG as "0.0.0.0/0 on port X." Neither asks:

1. Is this SG actually attached to a host?
2. Does that host have a public IP?
3. Does a TCP packet from outside complete a three-way handshake to that port?

**Evidence from 29-Apr live run (adf-pranapr).** Five SGs flagged for "MSSQL 1433
from 0/0":

- `AD-FACTOR-PROD-RDS-SG`, `ad-factor-rds-3-ondemand`, `ad-factor-rds-3-uat`,
  `radar-boundary-box-lambda-SG` — **0 instances attached** (orphan rules).
- `ADF-OpenVPN` (`13.232.207.52`) — 1 instance with public IP, but `:1433` and
  `:5432` time out on direct TCP probe (filtered upstream).
- `AD-FACTOR-PROD-ES-ASG` "9200 + 5601 from 0/0" — host `ADF-ElasticSearch`
  has **no public IP**, lives in a private subnet.
- Account contains **0 RDS instances**, period.

A SG-only audit reports 5 critical exposures. Reality is 0 reachable today, with
a real but secondary "config drift / future operator footgun" finding on the
orphan SGs.

**What to add.** New phase `whitebox/exposure/reachability.py`:

1. For every Finding produced by `analyze_security_groups`, walk
   `inventory/ec2/<region>.json` to map SG-id → instances using it.
2. Filter to instances with `PublicIpAddress`.
3. For each (public IP, port) pair, attempt `socket.create_connection((ip, port),
   timeout=4)` from the operator's egress.
4. Same for ELBv2: SG → load-balancer DNS → probe.
5. Annotate each Finding with one of three statuses:
   - `reachable` — handshake succeeded; severity unchanged or promoted.
   - `filtered` — SG open, host has public IP, packet dropped; severity
     downgraded to MEDIUM with note "config drift, not exploitable today."
   - `orphan` — SG open, no instance attached or no public IP; severity
     downgraded to LOW/INFO with note "policy hygiene."
6. Respect the existing scope-lock allowlist; do not probe anything outside it.
7. Add `--no-reachability` flag for offline runs (Prowler-only).

**Test plan.** Mock `socket.create_connection`. Cover orphan, filtered,
reachable, scope-blocked, ELBv2 paths.

---

## P1 — Route-table / VPC-peering reachability analyzer

**Problem.** Manual report Headline 1 ("Verified weak segmentation — VPC-2 ↔
PROD ↔ UAT ↔ RADAR-UAT active routes, UAT ↔ PROD bidirectional") is invisible
to our pipeline. Inventory does not pull `describe-route-tables` or
`describe-vpc-peering-connections`. Prowler has
`vpc_peering_routing_tables_with_least_privilege` but it does not produce the
CIDR-pair table the manual report needed.

**What to add.**
1. Inventory: `ec2 describe-route-tables` + `ec2 describe-vpc-peering-connections`
   for every region.
2. New module `whitebox/exposure/segmentation.py`: build a directed graph of
   `(VPC-A, VPC-B, peering-id, CIDR-mask, route-state)`; mark which VPCs host
   Internet-facing instances.
3. Emit a Finding per `Internet-VPC → PROD-VPC` active route, severity
   proportional to how broad the destination CIDR is (whole /16 vs /28).
4. Stale BLACKHOLE routes → INFO finding for cleanup.

---

## P2 — Detection-destination wiring checks

**Problem.** Manual report Headline 2 ("Detection signals exist but the
destinations are not wired"). Two distinct checks our pipeline does not run:

### 2a. EventBridge GuardDuty fan-out

For each account: confirm at least one rule with
`source: aws.guardduty / detail-type: GuardDuty Finding` exists, that its
target list is non-empty, and that the target is a real reachable destination
(SNS topic with subscribers, Lambda alias that exists, SIEM HTTP endpoint
configured, etc.).

### 2b. SNS subscriber-presence check

For every SNS topic referenced by an EventBridge rule or a CloudWatch alarm,
flag if `sns list-subscriptions-by-topic` returns zero confirmed subscribers.

**Evidence.** Manual report: "pranapr `security-alerts` SNS topic — zero
subscribers; CloudTrail-tampering and S3-LogBucket-tampering rules fire into
this topic. Tampering events go nowhere."

**What to add.**
1. Inventory: `events list-rules` + `events list-targets-by-rule` per region;
   `sns list-subscriptions-by-topic` per topic.
2. New module `whitebox/audit/destination_wiring.py`: cross-reference rule
   targets to live destinations; emit Finding when a rule fires into a void.

---

## P3 — SSM coverage check

**Problem.** Manual report Headline 3 ("Forensic agility on the anchor host
absent — EC2AMZ-D8IH8H1 not SSM-managed; ~37% of pranapr running fleet
similarly unmanaged"). We don't query `ssm describe-instance-information`.

**What to add.**
1. Inventory: `ssm describe-instance-information` per region.
2. New module `whitebox/iam/ssm_coverage.py`: intersect with `ec2
   describe-instances` (state=running); compute managed-vs-unmanaged ratio per
   account.
3. Emit one summary Finding per account ("X of Y running instances are
   SSM-managed, threshold 95%") plus a detail Finding listing the unmanaged
   instance IDs.

---

## P4 — CloudTrail recency + Backup Vault Lock

Two small additions to the audit normalizer / inventory.

**4a. CloudTrail recency.** For every trail, compare `CreatedTime` against the
engagement start date. If trail is < 90 days old, emit INFO Finding noting that
older management-plane visibility falls back on Event History.

**4b. Backup Vault Lock.** Inventory: `backup list-backup-vaults` +
`get-backup-vault-access-policy` + `backup-vault-lock-configuration`. Prowler
4.5 has no Vault Lock check. Emit MEDIUM Finding for any vault without Vault
Lock in compliance mode.

---

## P5 — Subscript: IIS / HTTPAPI fingerprinting on confirmed-reachable web hosts

When the P0 reachability phase confirms a public HTTP/HTTPS port is open, run a
focused fingerprint pass:

- Default IIS pages, `/iisstart.htm`, `/aspnet_client/`, `/trace.axd`.
- TLS handshake + cert SAN extraction.
- `Server: Microsoft-HTTPAPI/2.0` raw `http.sys` listeners (often forgotten
  WCF / self-hosted WebAPI; commonly missing auth).

Live run evidence: `13.232.36.49` and `13.202.204.62` both serve default IIS
10.0 pages from 2024; `13.202.204.62:443` returns `Microsoft-HTTPAPI/2.0` HTTP/2
404 — raw http.sys listener, not IIS-fronted.

This bridges the cloud-audit pipeline back into the existing blackbox scanner
(`scanner.sh`) which already knows how to probe IIS.

---

## P6 — Configurable phase timeouts (PMAPPER_TIMEOUT, dynamic Prowler timeout)

**Problem.** The 29-Apr live run against adf-pranapr (account 591335425990)
showed both upstream tools hit timeouts on a real account at scale:

- **Prowler:** 5400s (90 min) was insufficient for `--no-scope-lock` runs on
  this account. Status: failed, no OCSF output.
- **PMapper:** 1800s (30 min) was insufficient for the IAM graph build even
  with `PMAPPER_REGIONS=us-east-1,ap-south-1,eu-west-1`. Status: failed.

Today only `PROWLER_TIMEOUT` is configurable; PMapper's 1800s is hard-coded
in `whitebox/iam/pmapper_runner.py::build_graph(timeout=1800)`.

**What to add.**
1. New env var `PMAPPER_TIMEOUT` (parallel to `PROWLER_TIMEOUT`); plumb
   through orchestrator → `pmapper_runner.build_graph(timeout=...)`.
2. Document both in `CLAUDE.md` Whitebox section.
3. Optional: dynamic default — scale timeout by `(IAM users + roles + groups +
   policies)` count read from inventory before Prowler / PMapper start. Cap
   at 4 hours.
4. Reach-goal: split Prowler into per-service runs (`prowler aws --services
   iam,s3,ec2,...`) so partial timeouts only kill one service category, not
   the whole audit.

---

## P7 — Manifest coverage for secrets + correlation phases

**Problem.** On the 29-Apr live run, the orchestrator wrote 145 secret
evidence files to `secrets/` and the run exited cleanly (exit 0), yet the
session manifest only shows 4 phase entries (`inventory`, `prowler`, `iam`,
`exposure`) — no `secrets` or `correlation` entry. The phase clearly ran;
something between `_persist_phase_findings` (line 215) and
`cache.mark_complete("secrets", artifacts=...)` (line 226) silently swallowed
the manifest update.

**Reproduction.** Run `cloud_hunt --no-scope-lock --refresh` against
adf-pranapr; secrets dir fills with 145 files but manifest.json never gains a
`secrets` key.

**Investigation entry points:**
- `whitebox/orchestrator.py:172-231` (secrets phase block).
- `whitebox/cache/manifest.py:43-54` (atomic save — known good).
- Suspicion: an unhandled `BaseException` (not `Exception`) inside one of the
  later `run_secrets` sub-sources (ssm/secretsmanager/ec2_userdata) escapes the
  try block. Or `_persist_phase_findings` ran out of disk / hit a permission
  issue silently.

**Acceptance.** Manifest must record one of `complete` / `failed` for every
phase that was reached. Add an integration test that simulates a sub-source
raising an exception and asserts the manifest has `secrets: failed` not
absent.

---

## Tracking

When this lands in a real tracker (Linear, GitHub Issues), each section above
becomes one issue with the same heading, this file linking back as the source.
Until then, this is the canonical list.

# Gitleaks SARIF, Syft SBOM, and BagIt evidence packs

Opt-in supply-chain / evidence glue for Vikramaditya. **Not** on the default scan
path. No `ALLOW_STATE_CHANGES` / aggression default changes.

| Piece | Role | Default | Enable |
|---|---|---|---|
| **Gitleaks** (MIT) | Secret scan → SARIF/JSON → `finding_schema` / validator | OFF | `python3 gitleaks_report.py …` |
| **Syft** (Apache-2.0) | CycloneDX / SPDX SBOM attached to engagement packs | OFF | `python3 sbom_syft.py …` |
| **Grype** (Apache-2.0, optional) | Vuln scan of the SBOM | OFF | `--grype` on `sbom_syft.py` |
| **BagIt** (bagit-python CC0) | Hashed evidence bag (report + Burp + SARIF + SBOM + screenshots) | OFF | `python3 evidence_bag.py …` |

`setup.sh` already installs **gitleaks** via Homebrew. Syft / Grype / bagit-python
are optional — see Setup below.

## 1. Gitleaks → SARIF / findings

```bash
# Scan a checkout (dir mode; use --mode git for history)
python3 gitleaks_report.py \
  --source /path/to/repo \
  --findings-dir findings/acme.example.invalid

# Or ingest an existing Gitleaks JSON export
python3 gitleaks_report.py \
  --ingest-json /tmp/leaks.json \
  --findings-dir findings/acme.example.invalid \
  --sarif-out /tmp/gitleaks.sarif.json
```

Artefacts:

```
findings/<label>/
  gitleaks/
    gitleaks.json          # redacted / native JSON
    gitleaks.sarif.json    # SARIF 2.1.0
    findings.json          # Vik-normalized findings
    summary.json           # counts + validator bucket sizes
  exposure/
    gitleaks.txt           # report-walkable lines (secrets redacted)
```

Normalization uses `finding_schema.VerificationMethod.data_extracted` (secret
literally recovered from the artefact) so medium+ clears `should_report()`, then
runs `finding_validator.validate_finding` for the 7-question gate summary.

Env: `GITLEAKS_BIN=/path/to/gitleaks`

## 2. Syft SBOM (+ optional Grype)

```bash
# Generate CycloneDX + SPDX under engagements/<target>/sbom/
python3 sbom_syft.py \
  --target dir:/path/to/app \
  --pack-dir engagements/acme.example.invalid

# Also run Grype against the SBOM
python3 sbom_syft.py \
  --target dir:/path/to/app \
  --pack-dir engagements/acme.example.invalid \
  --grype

# Attach a pre-built SBOM only
python3 sbom_syft.py \
  --attach-only \
  --pack-dir engagements/acme.example.invalid \
  --sbom /tmp/sbom.cdx.json
```

Artefacts:

```
engagements/<target>/sbom/
  sbom.cdx.json
  sbom.spdx.json
  grype.json              # only with --grype
  attach_manifest.json
```

Env: `SYFT_BIN=…`  `GRYPE_BIN=…`

## 3. BagIt evidence packs

```bash
python3 evidence_bag.py \
  --pack-dir engagements/acme.example.invalid \
  --out engagements/acme.example.invalid/evidence-bags

# Explicit inputs (still merges discovery unless --no-discover)
python3 evidence_bag.py \
  --pack-dir engagements/acme.example.invalid \
  --report reports/acme.html \
  --burp findings/acme/burp \
  --sarif findings/acme/gitleaks/gitleaks.sarif.json \
  --sbom-dir engagements/acme.example.invalid/sbom \
  --screenshots reports/poc_screenshots
```

Produces a BagIt 0.97 bag with `manifest-sha256.txt` / `manifest-sha512.txt` and
`tagmanifest-*`. Prefers [bagit-python](https://github.com/LibraryOfCongress/bagit-python)
(CC0) when installed; otherwise uses a stdlib writer with the same layout.

```
engagements/<target>/evidence-bags/
  evidence-<UTC-stamp>/
    bagit.txt
    bag-info.txt
    manifest-sha256.txt
    tagmanifest-sha256.txt
    data/
      report/
      burp/
      sarif/
      sbom/
      screenshots/
      inventory.json
  evidence-<UTC-stamp>.summary.json
```

## Setup notes

```bash
# Already in setup.sh BREW_TOOLS / ALL_TOOLS:
brew install gitleaks

# Optional (not required for core VAPT; not failing setup.sh):
brew install syft grype
pip install 'bagit>=1.8.1'   # or: .venv/bin/pip install 'bagit>=1.8.1'
```

## Tests

```bash
pytest -q tests/test_gitleaks_report.py tests/test_sbom_syft.py tests/test_evidence_bag.py
```

All glue tests mock binaries / use synthetic placeholders only
(`*.example.invalid`, `AKIAIOSFODNN7EXAMPLE`). Never commit live engagement data.

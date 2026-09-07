# SARIF / HDF / ASFF export (MITRE SAF)

Vikramaditya writes Burp-style HTML/Markdown by default. This path is an **opt-in**
export for pipelines that need OASIS SARIF, Heimdall HDF, or AWS Security Hub ASFF.

## Design

1. **In-repo SARIF writer** (`saf_export.py`) maps validated finding dicts
   (reporter / finding_schema shape) to SARIF 2.1.0.
2. **Optional MITRE SAF CLI** converts further when `saf` is on `PATH`:
   - `saf convert sarif2hdf`
   - `saf convert hdf2asff`

Default scans never invoke this path.

## Install MITRE SAF CLI

See https://saf-cli.mitre.org/ — NPM package `@mitre/saf`, Homebrew formula
`mitre/saf/saf-cli`, or Docker image `mitre/saf`. Apache-2.0:
https://github.com/mitre/saf

## Invoke

Standalone (findings JSON list or wrapped object):

    python3 saf_export.py findings.json -o out.sarif.json
    python3 saf_export.py findings.json -o out.sarif.json --hdf out.hdf.json
    python3 saf_export.py findings.json -o out.sarif.json --hdf out.hdf.json \
      --asff out_asff/ --aws-account ACCOUNT --aws-region REGION

Via reporter (HTML/MD still written first; findings session dir):

    python3 reporter.py findings/<target>/sessions/<id>/ --export-sarif
    python3 reporter.py findings/<target>/sessions/<id>/ --export-hdf
    python3 reporter.py findings/<target>/sessions/<id>/ --export-asff \
      --asff-account ACCOUNT --asff-region REGION

Via orchestrator (opt-in; off by default) — PATH is a findings session dir
or a findings JSON file:

    python3 vikramaditya.py --export-sarif findings/<target>/sessions/<id>/
    python3 vikramaditya.py --export-sarif findings.json --sarif-output out.sarif.json
    python3 vikramaditya.py --export-sarif DIR --saf-hdf out.hdf.json --saf-asff asff_dir/

## Notes

- SARIF levels: critical/high → error, medium → warning, low/info → note.
- Reporter export uses the same verification gating as the HTML report.
- `--asff-upload` on reporter asks SAF to push to Security Hub when AWS creds
  are configured; default writes local ASFF files only.

# Tier-A recon enrichment — uncover / tlsx / waymore / xnLinkFinder

Extends Vikramaditya recon beyond the core `subfinder` / `gau` / `katana` path
with four complementary tools. Wired into `recon.sh` with **alterx-style
discipline**: full artefacts stay under the session recon directory; reports and
summaries only see **counts + samples** (`*.summary.json`).

No `ALLOW_STATE_CHANGES` / aggression default changes. Default scan path is
unchanged except for tools that already ran (tlsx, waymore) and xnLinkFinder
when installed.

## Tools

| Tool | Role | Default | Enable / knobs |
|---|---|---|---|
| **uncover** (ProjectDiscovery) | FOFA / Shodan / Censys / shodan-idb host discovery | **OFF** | `UNCOVER=1` |
| **tlsx** | TLS cert SAN / CN harvest after live probe | ON if installed | `TLSX_FEEDBACK=0` to skip merging in-scope SANs |
| **waymore** | Multi-source historical URLs (richer than gau alone) | ON in full recon (skipped `--quick`) | `WAYMORE_TIMEOUT`, `WAYMORE_MERGE_CAP` |
| **xnLinkFinder** | Richer JS / SPA endpoint mining (Next.js chunks, etc.) | ON if installed (skipped `--quick`) | `XNLINKFINDER_HOST_CAP`, `XNLINKFINDER_MERGE_CAP`, `XNLINKFINDER_DEPTH` |

## Artefact layout

Under `recon/<target>/` (or the session recon dir):

```
uncover/
  raw.txt              # raw uncover stdout (gitignored session data)
  hosts.txt            # normalized hosts / host:port
  summary.json         # {count, sample[≤20]} — safe for report references
  idb_raw.txt          # optional post-live shodan-idb pass
certs/
  sans.txt             # tlsx SAN/CN values
  in_scope_new.txt     # SANs under the target apex not already in all.txt
  scope_candidates.txt # all SANs not in subdomain enum (incl. out-of-scope)
  summary.json         # count + samples (in-scope / out-of-scope)
urls/
  waymore.txt          # merge-capped URL list (feeds urls/all.txt)
  waymore.full.txt     # only when over WAYMORE_MERGE_CAP
  waymore.summary.json
js/xnlinkfinder/
  targets.txt          # capped live URL inputs
  endpoints.txt        # merge-capped endpoints (also folded into js/endpoints.txt)
  endpoints.full.txt   # only when over XNLINKFINDER_MERGE_CAP
  params.txt
  summary.json
subdomains/
  uncover.txt          # hostname seeds from uncover
  tlsx_sans.txt        # in-scope SAN feedback copy
  xnlinkfinder.txt     # in-scope hosts mined from JS
```

## uncover (opt-in)

Most engines need API keys in `~/.config/uncover/provider-config.yaml` or env
(`SHODAN_API_KEY`, `FOFA_EMAIL`+`FOFA_KEY`, `CENSYS_API_ID`+`CENSYS_API_SECRET`).
`shodan-idb` is keyless and runs against `live/ips.txt` after Phase 3 when
`UNCOVER=1`.

```bash
UNCOVER=1 UNCOVER_ENGINES=shodan,shodan-idb UNCOVER_LIMIT=100 \
  bash recon.sh example.com
```

## waymore merge cap

`WAYMORE_MERGE_CAP` (default `50000`) mirrors `ALTERX_MERGE_CAP`: when the archive
pull is huge, the full set is kept as `urls/waymore.full.txt` and only the capped
prefix merges into `urls/all.txt`. Operators raise the cap or set `0` for unlimited.

## xnLinkFinder

Installed via `pip3 install xnLinkFinder` (`setup.sh`). Runs after LinkFinder on a
capped live-host list (`XNLINKFINDER_HOST_CAP`, default 15), depth
`XNLINKFINDER_DEPTH` (default 1), scoped with `-sf $TARGET`. Absolute in-scope
hosts found in JS are seeded into `subdomains/all.txt` for later / resume runs.

## Python glue

`recon_enrichment.py` — parsers + summary writers used by `recon.sh`:

- `summarize` / `cap-merge` / `parse-uncover` / `parse-xnlinkfinder` / `tlsx-feedback`

Tests: `tests/test_recon_enrichment.py`.

## Install

```bash
bash setup.sh
# or individually:
go install github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
pip3 install waymore xnLinkFinder
```

`hunt.py --repair-tools` can restore registry entries (`uncover`, `tlsx`,
`waymore`, `xnLinkFinder`).

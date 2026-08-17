"""
fetch_and_publish_asx_csv.py -- v1.0

GitHub Actions RUNNER-SIDE fetch + publish script for the asx-universe-
fetcher Lambda's alt-transport pull model.

Design authority: ASX_Universe_Fetcher_Fallback3_Design_v0_1.md (v0.5),
Half one, §3 specifically -- Matt's chosen PULL model (§3.2b): this script
runs on a GitHub-hosted Actions runner (non-AWS egress -- a different
Autonomous System Number from AWS Lambda). It independently re-fetches the
SAME two official ASX CSV sources the asx-universe-fetcher Lambda tries
directly, using the same class of plausibility checks the Lambda already
applies (not-HTML/not-a-block-page, header row present, row-count floor).
On the FIRST source that passes, it publishes the raw CSV bytes UNCHANGED,
plus a freshness sidecar manifest, to published/ in THIS repository -- for
the Lambda to read over plain HTTPS (raw.githubusercontent.com). This is
"the same client honesty, same URLs, same columns, just a different egress
IP" (design §3.1) -- explicitly NOT the browser-fingerprint-defeat approach
the companion WAF-block design already declined.

THIS REPOSITORY MUST BE A DEDICATED, MINIMAL, PUBLIC REPOSITORY -- NOT the
main asx-pipeline working tree (design §3.2b "Repository shape"). Public is
required so the Lambda can read published/ over plain HTTPS with zero AWS
credential and zero GitHub token -- the CSV is already-public ASX data, so
this leaks nothing.

WHAT THIS SCRIPT DOES NOT DO:
  - Does not parse/derive GICS fields, tickers, or any universe.json shape.
    It publishes the raw CSV bytes exactly as received -- all authoritative
    parsing, case-insensitive header-alias binding, and consumer-facing
    derivation stays the Lambda's job (design §3.6: "the transport is never
    trusted blindly" -- the Lambda re-validates and re-parses this file
    exactly as it would a direct fetch). The row-count check here is a
    cheap PUBLISH-WORTHINESS check only, not the authoritative parse.
  - Does not touch AWS in any way. No boto3, no AWS credential of any kind,
    no OIDC. This is the whole point of the pull model (design §3.2b): zero
    new AWS credential, zero new IAM identity.
  - Does not overwrite published/ on a failed run. A stale-but-present
    published CSV is safer than an unvalidated one; the Lambda-side P-ALT
    freshness gate (see ALT_TRANSPORT_MAX_AGE_DAYS in the Lambda source) is
    what protects against staleness, not this script refusing to publish.
    It DOES always write published/heartbeat.json (see KEEPALIVE below),
    even on a total failure, so the run's outcome is visible in the repo
    without needing to dig through Actions run history.

KEEPALIVE (design §3.5): GitHub documents that `schedule`-triggered
workflows are automatically disabled after a period of repository
inactivity. A dedicated, minimal, otherwise-commit-less runner repo is
exactly that profile. This script always writes published/heartbeat.json
-- win or lose -- and the companion workflow YAML always commits it (even
when the fetch step failed), so the repository shows real weekly git
activity regardless of fetch outcome. This is a MITIGATION, not a
guarantee (the exact current auto-disable threshold and behaviour is a
build-stage verify-in-hand item per the design's own §9 item 7 -- do not
assume the commonly-cited ~60-day figure without checking GitHub's current
docs at setup time). The Lambda-side mandatory ALT_TRANSPORT_STALE check
(folded into its own weekly run, design §3.5) is the real safety net if
this keepalive is ever insufficient on its own.

EXIT CODE: 0 on a successful publish. 1 if every source failed validation
-- the workflow step (and so the whole run) then shows FAILED in the
GitHub Actions UI (design §3.3: "on total failure -> publish nothing;
workflow fails loudly").

MANUAL SETUP REQUIRED (Matt, one-off -- none of this is done by this
script or by the Lambda):
  1. Create a NEW, dedicated, PUBLIC GitHub repository (design §3.2b --
     do not reuse the asx-pipeline working-tree repo).
  2. Copy this script to <repo>/scripts/fetch_and_publish_asx_csv.py and
     the companion workflow YAML
     (2026-08-17_asx_universe_alt_transport_v1_0_0800.yml, same folder as
     this file) to <repo>/.github/workflows/asx_universe_alt_transport.yml.
  3. Push once (an empty published/ folder is not required -- the first
     workflow run creates published/*.json and published/*.csv itself).
  4. On the asx-universe-fetcher Lambda, set the environment variables
     ALT_TRANSPORT_GITHUB_OWNER and ALT_TRANSPORT_GITHUB_REPO to the real
     GitHub owner/repo (and ALT_TRANSPORT_GITHUB_BRANCH only if not
     "main"). No redeploy is needed for a later repo rename -- these are
     environment variables, not hardcoded constants, on the Lambda side.
  5. No GitHub secrets are needed. The workflow's built-in, automatically-
     provisioned GITHUB_TOKEN (granted contents:write by the workflow's own
     `permissions:` block) is sufficient to commit and push -- this is
     STILL zero new credentials in the sense the design cares about (no
     AWS credential, no long-lived secret Matt has to create or rotate).
  6. Trigger the workflow manually once (`workflow_dispatch`, in the
     Actions tab) to confirm the whole chain end-to-end before relying on
     the schedule.

VERIFY BEFORE FIRST RELIANCE (not verified by this script -- design §9
item 8, a build blocker for the pull model): confirm the Lambda's own
environment (ap-southeast-2) can actually reach
raw.githubusercontent.com unauthenticated. This script's own successful
runs do not prove that -- GitHub-hosted-runner egress and AWS Lambda
egress are different networks. See the Lambda source's docstring for the
live-verification status of that specific check.
"""

import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Same two official sources the Lambda tries directly. Keep this list in
# sync with ASX_CSV_SOURCES in the Lambda source
# (2026-08-17_asx_universe_fetcher_v1_3_0748.py or its successor) if either
# URL ever changes -- there is no shared config file between the two repos,
# so this sync is a manual discipline, not an automated one.
# ---------------------------------------------------------------------------
SOURCES = (
    (
        "markitdigital_directory",
        "https://asx.api.markitdigital.com/asx-research/1.0/companies/directory/file"
        "?access_token=83ff96335c2d45a094df02a206a39ff4",
    ),
    ("legacy_asx", "https://www.asx.com.au/asx/research/ASXListedCompanies.csv"),
)

# Plausibility floors -- deliberately the SAME values as the Lambda's
# CSV_SIZE_FLOOR_BYTES / TICKER_COUNT_FLOOR (design placeholders,
# [placeholder, TBD Matt] -- see ASX_Universe_Fetcher_WAF_Block_Design_v0_1.md
# §9 P1/P2). Kept in sync deliberately: there is no principled reason for the
# runner's "plausible enough to publish" bar to differ from the Lambda's
# "plausible enough to use directly" bar.
CSV_SIZE_FLOOR_BYTES = 10_000
ROW_COUNT_FLOOR = 1_500

HTTP_TIMEOUT = 45
USER_AGENT = "asx-alt-transport-publisher/1.0"

PUBLISHED_DIR = Path("published")
CSV_OUT = PUBLISHED_DIR / "ASXListedCompanies.csv"
MANIFEST_OUT = PUBLISHED_DIR / "manifest.json"
HEARTBEAT_OUT = PUBLISHED_DIR / "heartbeat.json"


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_like_block_page(raw_bytes: bytes) -> bool:
    """Cheap heuristic mirroring the Lambda's own plausibility check -- NOT
    the authoritative check (the Lambda fully re-validates on read, per
    design §3.6); just enough to avoid publishing an obvious Incapsula/
    Imperva reject page or an HTML error page as if it were a CSV."""
    if len(raw_bytes) < CSV_SIZE_FLOOR_BYTES:
        return True
    head = raw_bytes[:2000].lower()
    stripped = head.lstrip()
    if stripped.startswith(b"<!doctype") or stripped.startswith(b"<html"):
        return True
    for marker in (b"request rejected", b"incapsula", b"imperva"):
        if marker in head:
            return True
    return False


def _row_count_check(raw_bytes: bytes):
    """Locate the header row (search for the literal 'ASX code', same
    approach as the Lambda) and do a coarse row count. Returns
    (ok: bool, row_count: int|None). This is NOT the Lambda's full
    case-insensitive alias-mapped header binding -- that authoritative
    parse happens Lambda-side on read (design §3.6). This is only a
    publish-worthiness check, kept deliberately simple."""
    text = raw_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if "ASX code" in line:
            header_idx = i
            break
    if header_idx is None:
        return False, None
    data_lines = [ln for ln in lines[header_idx + 1:] if ln.strip()]
    row_count = len(data_lines)
    return row_count >= ROW_COUNT_FLOOR, row_count


def _fetch_one(source_kind: str, url: str):
    """Returns (raw_bytes, row_count) on success, or (None, reason_str) on
    failure. Never raises -- caller tries the next source."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw_bytes = resp.read()
    except urllib.error.URLError as exc:
        return None, f"download failed: {exc}"

    if _looks_like_block_page(raw_bytes):
        return None, f"body implausible (block page or too small, {len(raw_bytes)} bytes)"

    ok, row_count = _row_count_check(raw_bytes)
    if not ok:
        return None, f"row count below floor ({row_count} < {ROW_COUNT_FLOOR}, or header not found)"

    return raw_bytes, row_count


def _write_heartbeat(status: str, detail: str) -> None:
    PUBLISHED_DIR.mkdir(parents=True, exist_ok=True)
    HEARTBEAT_OUT.write_text(
        json.dumps(
            {
                "last_run_at": _utc_iso(),
                "last_run_status": status,
                "detail": detail,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> int:
    attempts = []
    for source_kind, url in SOURCES:
        raw_bytes, result = _fetch_one(source_kind, url)
        if raw_bytes is None:
            attempts.append(f"{source_kind}: {result}")
            print(f"UNUSABLE source={source_kind} reason={result}")
            continue

        row_count = result
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        fetched_at = _utc_iso()

        PUBLISHED_DIR.mkdir(parents=True, exist_ok=True)
        CSV_OUT.write_bytes(raw_bytes)
        MANIFEST_OUT.write_text(
            json.dumps(
                {
                    "fetched_at": fetched_at,
                    "source_kind": source_kind,
                    "source_url": url,
                    "row_count": row_count,
                    "size_bytes": len(raw_bytes),
                    "checksum_sha256": checksum,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        _write_heartbeat("published", f"source={source_kind} row_count={row_count}")
        print(f"PUBLISHED source={source_kind} row_count={row_count} bytes={len(raw_bytes)}")
        return 0

    # Total failure -- publish nothing (design §3.3: never overwrite a
    # working published CSV with a bad one), but still write the heartbeat
    # so the repo shows this week's activity (design §3.5 keepalive) and so
    # a human reading published/heartbeat.json sees the run happened and
    # failed, rather than the run simply vanishing.
    detail = "; ".join(attempts)
    _write_heartbeat("failed", detail)
    print(f"FAILED all sources unusable: {detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

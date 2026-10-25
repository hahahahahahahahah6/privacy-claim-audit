# privacy-claim-audit

Version 0.1.0. A stdlib-only Python CLI that checks a project's own privacy
and offline claims against static Python network evidence. Works offline,
never executes project code, and makes no network requests.

## Usage

Requires Python 3.9 or later. Install a locally built wheel:

```sh
python3 -m pip install --no-index dist/privacy_claim_audit-0.1.0-py3-none-any.whl
privacy-claim-audit [path] [--json] [--fail-on HIGH|MEDIUM] [--ignore RULE,...] [--verbose] [--version]
privacy-claim-audit .
privacy-claim-audit tests/fixtures/good --json
privacy-claim-audit tests/fixtures/bad --ignore offline-claim-false
privacy-claim-audit . --fail-on HIGH --verbose
python3 -m privacy_claim_audit --version
```

The default path is `.`. Exit codes: **0 PASS**, **2 FAIL**, **1 usage/input
error**. The default threshold is MEDIUM; HIGH leaves MEDIUM findings visible
without failing. `--ignore` drops named rules entirely, for example when a
project documents an intentional exception; unknown rule names are usage errors.
`--verbose` prints verified claims in human output. `--version` prints `0.1.0`.
Human findings use `SEVERITY rule file:line message`, followed by PASS or FAIL.
Locations point to the claim; the message names the first evidence file:line.
Only locations, matched claim phrases and rule names are reported, never source
line contents. Syntax errors and unreadable source/docs are input errors.

JSON always includes `status`, `findings`, and `verified_claims`. Findings have
`severity`, `rule`, `file`, `line`, and `message`, sorted by `(rule, file, line)`
with message as a deterministic tie-breaker. Verified claims have `claim` and
`file`. PASS means no contradictions detected at the selected threshold; a
verified claim is a static scan result, not a proof of runtime privacy. Ignoring
a contradiction does not turn it into a verified claim.

## Full rule table

| Rule | Severity | Trigger |
| --- | --- | --- |
| `offline-claim-false` | HIGH | An offline-claim is present in docs AND any non-test source file has network-import or network-call evidence. Message names the claim phrase, the doc file, and the first evidence file:line. |
| `local-only-claim-false` | HIGH | A local-only-claim is present in docs AND any non-test source file has network-import, network-call, or hardcoded-endpoint evidence. |
| `no-telemetry-claim-false` | HIGH | A no-telemetry-claim is present in docs AND any non-test source file has telemetry-import evidence, OR a network-call to a known analytics host as a literal host in a URL string. A generic network call alone does NOT trigger this rule. |
| `test-only-network` | MEDIUM | Network evidence exists ONLY in test files while an offline/local-only claim is present in docs. Tests may legitimately use a local server fixture; this is informational at MEDIUM so a human can confirm the tests do not hit the network. |
| `claim-without-evidence-note` | Not a finding | When a claim is present and no evidence is found, reports PASS and lists verified claims (claim phrase + doc file) under JSON `verified_claims`. Human output prints them only with `--verbose`. |

Rule 3 always requires a no-telemetry claim, including its analytics-host branch.
Each matched claim occurrence can produce a finding. Tests never trigger rules
1–3. An individual claim is verified when no relevant contradiction is found.

## Detection and scope

Reads README.md and other top-level `*.md` files, and recursively scans Python
`*.py` source including root modules, src/, package directories and tests.
Skips `.venv`, `venv`, `__pycache__`, `dist`, `build`, `.git`, and directories
ending in `.egg-info`; symbolic links are skipped. It never reads `.env` or
other non-source/non-documentation file contents. Claims in code comments or
nested documentation do not count.

Claim regexes are case-insensitive, literal phrase alternatives surrounded by
word boundaries (`\b(?:phrase|...)\b`). Longer alternatives are tried first
so “fully offline” is one match rather than a second overlapping “offline”.
The complete phrase lists are:

- **offline-claim**: `offline`, `works offline`, `fully offline`, `no internet`, `no network`, `no network access`, `does not require internet`, `no internet required`.
- **local-only-claim**: `local only`, `local-only`, `runs locally`, `stays on your machine`, `never leaves your machine`, `data never leaves`, `your data stays`.
- **no-telemetry-claim**: `no telemetry`, `no tracking`, `no analytics`, `no phone home`, `no data collection`, `does not collect`, `does not send`, `does not transmit`, `does not upload`, `does not phone home`.

Source evidence uses AST imports/calls and regex matching of string literals:

- `network-import`: requests, httpx, urllib.request, urllib3, aiohttp, socket,
  smtplib, ftplib, websocket, websockets, telnetlib. Handles import/from forms
  and aliases; only urllib.request, not all of urllib, is network evidence.
- `network-call`: urlopen, requests.get/post/put, httpx.get/post,
  socket.socket/connect, smtplib.SMTP, and subprocess calls containing a
  literal `curl` or `wget` argument in an argument list.
- `telemetry-import`: sentry_sdk, posthog, mixpanel, amplitude, segment,
  analytics, telemetry, datadog, newrelic, honeycomb, plausible.
- Known analytics hosts: segment.io, amplitude.com, mixpanel.com, posthog.com,
  sentry.io, google-analytics.com, googletagmanager.com. Subdomains count;
  unrelated hosts with a matching prefix do not. A URL must occur in a
  detected network call, not merely in an unused constant.
- `hardcoded-endpoint`: a code string matching
  `https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}` outside tests and docstrings.
  Module, class and function docstrings are skipped for this rule.

## Differentiation

  - vs bandit: bandit finds security issues in code; this checks
    whether the project's OWN privacy prose is true — no vuln
    detection, no severity scoring of code issues.
  - vs pip-audit: pip-audit checks installed packages against a
    vulnerability database (needs the network/registry); this audits
    the repo's claims statically, offline, and never asks whether a
    package is vulnerable.
  - vs consent-engine: that runs a live browser against a deployed
    web page and checks consent behaviour at runtime; this audits a
    repo's static claims before anything runs.
  - vs privacyaudit (PyPI): that audits trained ML models for
    membership-inference risk; this audits prose claims vs source
    network behaviour — different input, different question.
  - vs readme-claim-audit / dep-claim-audit: those audit install,
    flag, link, version, and dependency claims; this audits privacy /
    offline claims only — no overlap in rules.

## Honest limitations

static scan misses dynamic
  network access (importlib-loaded modules, exec/eval of fetched code,
  plugins loaded at runtime); a network import that is never called at
  runtime still triggers a finding (human must confirm reachability);
  prose claim detection is pattern-based not semantic (a sentence like
  "we removed offline mode" could false-positive — scope prose search
  to README + top-level docs and document the regex list); telemetry
  SDK list is small and documented — unknown SDKs are not flagged;
  hardcoded-endpoint skips docstrings, so an endpoint documented only
  in a docstring is not counted as evidence.

Import aliases are resolved statically without control-flow analysis. Arbitrary
object method calls, dynamically assembled URLs, shell command strings and
transitive dependencies are outside the detector's finite call list.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PIP_NO_INDEX=1 python3 -m build
# If isolated build requirements are unavailable locally:
PIP_NO_INDEX=1 python3 -m build --no-isolation
```

Tests use only local fixtures and temporary directories. Package runtime has no
third-party dependencies. MIT licensed; see LICENSE.

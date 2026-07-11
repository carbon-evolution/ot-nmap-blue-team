# Phase 1 Design — Quality Gaps + Mock-Driven CI Harness

**Date:** 2026-07-11
**Project:** ot-nmap-blue-team (OT/ICS Nmap NSE discovery scripts + honeypot mock servers)
**Status:** Approved — ready for implementation planning

## Context

The repo ships 13 "improved" NSE discovery scripts and 7 Python mock servers. All
scripts pass `luac -p`, and GE SRTP / FF HSE are verified end-to-end. But there is
no automated testing and two known quality gaps remain:

- **FF HSE** (`ff-hse-discover-improved.nse`) emits generic `field_1`/`field_2`
  strings instead of the seven named fields the README promises, and its mock
  returns the same identity regardless of `--profile`.
- **Red Lion** (`redlion-cr3-info-improved.nse`) has never been verified
  end-to-end because its portrule is pinned to privileged TCP 789.

This is the first of three phases (Phase 2 = more protocols, Phase 3 = blue-team
output). Phase 1 pairs the quality fixes with a test harness because building the
tests *is* how the gaps get fixed and proven.

## Goals

1. A pytest harness that boots each mock, runs the matching NSE script, and asserts
   the expected fields — covering all 13 scripts.
2. FF HSE reworked to full documented fidelity (named fields + per-profile identity).
3. A profile-fidelity sweep confirming profile-capable mocks actually vary output.
4. Red Lion verified end-to-end (privileged test).
5. GitHub Actions CI running syntax checks + the full suite on every push/PR.

Non-goals: new protocols (Phase 2), structured scan output/orchestration (Phase 3),
changes to the 6 lesser-known mocks beyond FF HSE unless the sweep requires them.

## Design

### 1. Test harness (`sandbox/tests/`)

- **`conftest.py`**
  - `mock_server(script, port, *args)` context manager / fixture factory: launches a
    mock as a subprocess, polls a TCP connect to `127.0.0.1:port` until it accepts
    (timeout ~10s), yields, then terminates and reaps the process on exit (including
    on assertion failure).
  - `nmap_scan(port, script_path, script_args=None) -> dict`: runs
    `nmap -p <port> --script <script_path> [--script-args ...] 127.0.0.1`, captures
    stdout, and parses the `| <script>:` output block into a `{field: value}` dict
    (handles the `|`, `|_` line prefixes and `key: value` rows).
- **`test_<protocol>.py`** (one module per script, 13 total)
  - Assert the expected named fields are present and non-empty.
  - For scripts whose mocks expose profiles, start the mock under two different
    profiles and assert at least one extracted field differs — this is the concrete
    check that profiles are not ignored.
- **Red Lion**: test decorated `@pytest.mark.privileged`, auto-skipped when
  `os.geteuid() != 0`; binds the mock on 789 and scans 789.
- **`requirements.txt`** — `pytest`. **`pytest.ini`** — registers the `privileged`
  marker and sets `testpaths = sandbox/tests`.

Standard-vs-lesser-known note: the 6 lesser-known scripts use their standalone
honeypot mocks. The 7 standard scripts share `ot_mock_servers.py`. During
implementation, if the all-in-one mock does not faithfully serve a given standard
protocol on its port, that script's test either gets a small dedicated mock or is
marked `xfail` with an explicit reason — never silently skipped.

### 2. FF HSE rework

- **`ffhse_mock_server.py`**: the MA_IDENTIFY handler returns a structured response
  carrying seven fields — Device Name, Vendor, Device Tag, HSE Version, Software
  Revision, Stack, MAC — with **distinct values for each of the four profiles**
  (temperature, pressure, flow, valve).
- **`ff-hse-discover-improved.nse`**: parser upgraded to extract those seven named
  fields into the output table, preserving the `pcall` guard around
  `string.unpack("z", ...)` added in commit `4ee8e6a`.
- Test asserts all seven fields plus a profile-difference.

### 3. Profile-fidelity sweep

Confirm the other profile-capable mocks (GE SRTP, MELSEC-Q, OPC UA, ProConOS, Red
Lion) genuinely vary the fields their NSE scripts extract. Fix any that don't. Keep
scope minimal unless the sweep surfaces more offenders; each fix gets a
profile-difference assertion in its test.

### 4. CI workflow (`.github/workflows/ci.yml`)

Trigger: `push` and `pull_request`. Ubuntu runner. Steps:

1. `actions/checkout`
2. `sudo apt-get update && sudo apt-get install -y nmap lua5.4`
3. `actions/setup-python` + `pip install -r sandbox/tests/requirements.txt`
4. Syntax gate: `luac -p` over every `.nse` in `improved-scripts/` (recursive);
   fail on any error.
5. `pytest -m "not privileged"` — the 12 unprivileged scripts.
6. `sudo pytest -m privileged` — Red Lion on 789.

Any parser regression or field mismatch turns the run red. Optionally emit JUnit XML
as a build artifact (nice-to-have, not required).

## Testing Strategy

The harness *is* the testing strategy: every script has at least one field-presence
test, and every profile-capable script has a profile-difference test. Red Lion's
privileged test closes the last unverified gap. CI enforces all of it per push.

## Risks / Open Questions

- **All-in-one mock fidelity** for the 7 standard protocols (see harness note) —
  resolved per-script during implementation (dedicated mock or documented `xfail`).
- **`sudo pytest` env**: the privileged step must preserve PATH so `nmap`/`python`
  resolve under sudo; use `sudo -E` or an explicit env as needed.
- The gitignored static `sandbox/test-results/*.txt` files are superseded by the
  harness; left in place but no longer the source of truth.

## Out of Scope (future phases)

- Phase 2: new protocol scripts + mocks (BACnet, EtherNet/IP CIP, OMRON FINS,
  S7comm-plus, CODESYS, …).
- Phase 3: structured JSON/CSV asset-inventory output, scan-orchestration wrapper,
  CVE-correlation hints.

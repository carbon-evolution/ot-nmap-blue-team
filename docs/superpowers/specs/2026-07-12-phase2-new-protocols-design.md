# Phase 2 Design — Three New OT Protocols (EtherNet/IP, BACnet/IP, S7comm-plus)

**Status:** Approved 2026-07-12. Follows [Phase 1](2026-07-11-phase1-quality-ci-design.md) (quality gaps + CI harness, merged to `main`).

## Goal

Extend the toolkit with three new T1-safe, read-only OT discovery scripts — EtherNet/IP
CIP, BACnet/IP, and S7comm-plus — each paired with a honeypot-grade mock server, a
mock-driven pytest test, and CI coverage, at the same standard as the existing 13
scripts. Also extend the test harness to scan UDP, which gives BACnet real automated
coverage and retroactively converts the Phase 1 PROFINET-CM `xfail` into a real
passing test.

This is the second of three phases (Phase 1 = quality/CI, done; Phase 3 = structured
blue-team output). Only Phases 1 and 2 are designed.

## Pattern (mirrors Phase 1)

Each protocol follows the established repo pattern — improve an upstream community
script rather than writing from scratch:

1. Take the upstream Redpoint script → write `improved-scripts/<proto>-...-improved.nse`.
2. Build a standalone honeypot-grade mock in `sandbox/<proto>_mock_server.py` with
   `--port` and `--profile` device variants (matching the 6 lesser-known mocks:
   protocol state machine, per-profile device identity, detection logging, scan-delay
   jitter).
3. Add `sandbox/tests/test_<proto>.py` — field-presence assertions on the REAL NSE
   output labels (verified live or, for privileged ports, by code-reading the
   mock+NSE and reconciling as Phase 1 did for Red Lion/Modbus), plus a
   profile-difference assertion.
4. CI needs no new wiring: the `luac -p` gate globs all `.nse`; the unprivileged and
   privileged pytest jobs already exist.

All scripts stay **T1 (basic read) safe** — identity/fingerprint reads only, no
configuration reads, no writes.

## Per-Protocol Design

### 1. EtherNet/IP CIP — the clean one

- **Transport / port:** TCP **44818** (encapsulation / explicit messaging). Unprivileged.
- **Method:** `ListIdentity` (encapsulation command 0x0063) — a single request/response,
  read-only, returns the Identity CIP object.
- **Extracted fields:** Vendor ID (+name), Device Type, Product Code, Revision
  (major.minor), Status/Device State, Serial Number, Product Name.
- **Base:** `Redpoint/enip-enumerate.nse`.
- **Mock profiles:** Allen-Bradley ControlLogix (1756-L61), Allen-Bradley Micro850
  (2080-LC50), and a third-vendor CIP device (e.g. Omron NX). Each profile varies
  Vendor/Product Code/Serial/Product Name.
- **Test:** unprivileged, live-verified. `test_enip.py` asserts `product name` +
  `serial number` present with a profile's real values, and profiles differ on
  `product name`.

### 2. BACnet/IP — building automation

- **Transport / port:** UDP **47808** (0xBAC0). Requires the new UDP harness path;
  test is **privileged** (nmap `-sU` needs root).
- **Method:** Who-Is / ReadProperty on the Device object, reading standard properties.
  Read-only.
- **Extracted fields:** object-name, vendor-name (+vendor-id), model-name,
  firmware-revision, application-software-version, location, description.
- **Base:** `Redpoint/BACnet-discover-enumerate.nse`.
- **Mock profiles:** an Automated Logic controller, a Siemens BAS device, and a
  Honeywell BAS device. Each varies vendor/model/firmware/object-name.
- **Test:** privileged + UDP, reconciled by code-reading if root isn't available
  locally (verified live under CI-root). Asserts `vendor name` + `model name` present,
  profiles differ on `model name`.

### 3. S7comm-plus — Siemens S7-1200/1500 (highest risk)

- **Transport / port:** TCP **102** (COTP / ISO-TSAP). **Privileged** (<1024, root).
  The Phase 1 MMS mock in `ot_mock_servers.py` also uses 102, so the S7 mock takes a
  configurable `--port` (default 102) — the privileged test binds 102 as root; nothing
  collides because the MMS mock is a separate process not started during the S7 test.
- **Method:** COTP connection request → S7comm-plus identification exchange. Extract
  device identity where the device answers: Module / Order number (MLFB), hardware and
  firmware version, serial number, PLC/station name. This combines the classic-S7
  SZL-style identification (many S7-1200/1500 still answer) with the S7comm-plus
  handshake fingerprint.
- **Base:** `Redpoint/s7-enumerate.nse` + `ICS-Discovery-Tools/s71200-enumerate-old.nse`.
- **Mock profiles:** S7-1200 (6ES7 212-...) and S7-1500 (6ES7 515-...). Each varies
  order number / firmware / serial / station name.
- **FIDELITY FALLBACK (stated up front):** S7comm-plus (S7-1200/1500) is more opaque
  than classic S7comm. If a faithful full S7comm-plus identity read proves intractable
  to emulate + parse within a mock, the script + mock are scoped down to the
  COTP-connect + S7comm-plus initial-probe **fingerprint** that IS verifiable (protocol
  present, device family distinguishable by profile), and the limit is documented in
  the script header and the test. **Never** fake or weaken a passing assertion — if the
  full identity read can't be driven, the test asserts the verifiable fingerprint fields
  and, if even that is not faithful, is marked `xfail` with a specific reason (as Phase 1
  did for redacted/UDP protocols). Every script still ships with a test function.
- **Test:** privileged, reconciled by code-reading (root-only port), verified under
  CI-root. Asserts the identity/fingerprint fields the mock+NSE actually produce, and
  profiles differ.

## Harness UDP Extension

- Add a UDP scan path to `sandbox/tests/conftest.py`: extend `nmap_scan` with a
  `udp=False` parameter (or a sibling `nmap_scan_udp`) that runs `nmap -sU -p <port>`
  instead of TCP. UDP scanning requires root, so UDP-based tests carry the existing
  `privileged` marker + `skipif(os.geteuid() != 0)`.
- Keep the change minimal and non-breaking (default `udp=False`; all existing call
  sites unchanged), exactly like the Phase 1 `inject_port` extension.
- **Retroactive win:** convert the Phase 1 `test_profinet` from `xfail` to a real
  privileged UDP test using the new path (the PROFINET-CM mock already exists in
  `ot_mock_servers.py`; only the harness lacked UDP).

## Port / Privilege Summary

| Protocol | Port | Transport | Test class | Verified |
|---|---|---|---|---|
| EtherNet/IP CIP | 44818 | TCP | unprivileged | live |
| BACnet/IP | 47808 | UDP | privileged (root, new UDP path) | CI-root / code-read |
| S7comm-plus | 102 | TCP | privileged (root) | CI-root / code-read |
| PROFINET-CM (retro) | 34964 | UDP | privileged (root, new UDP path) — was xfail | CI-root |

## Testing & CI

- One `test_<proto>.py` per new script, following the Phase 1 test idiom
  (`mock_server` fixture + `nmap_scan` + `parse_fields`, field-presence +
  profile-difference assertions).
- Privileged/UDP tests use `@pytest.mark.privileged` + `skipif(geteuid != 0)`; they
  run as root in the existing CI `privileged` job.
- The `luac -p` syntax gate and both pytest jobs in `.github/workflows/ci.yml` already
  cover new files with no workflow change.
- Assertions target the REAL NSE output labels (assumed field names are not trusted —
  Phase 1 proved they can be wrong; reconcile against the mock + NSE).

## Out of Scope (deferred)

- Other candidate protocols: OMRON FINS, CODESYS, S7comm-classic-only.
- Phase 3: structured JSON/CSV asset-inventory output, scan-orchestration wrapper,
  CVE-correlation hints.

## Risks

- **S7comm-plus fidelity** — the known hard item; handled by the explicit fallback above.
- **Privileged-only verification** — BACnet (UDP) and S7comm-plus (port 102) can't be
  fully run locally without root; assertions are reconciled by code-reading and first
  truly execute under CI-root, exactly as Modbus/MMS/Red Lion did in Phase 1. CI is the
  gate.
- **UDP scan flakiness** — UDP scans can be slower/less deterministic; the mock must
  respond promptly and the test timeout must accommodate `-sU`.

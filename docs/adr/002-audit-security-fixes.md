# ADR-002: Security Audit Fixes

**Date:** 2025-07-14
**Status:** Accepted
**Author:** Security Audit (Copilot)

## Context

A security-first audit of `convergio-org-package` was performed covering:
SQL injection, path traversal, command injection, SSRF, secret exposure,
race conditions, unsafe blocks, input validation, and auth/authz bypass.

## Findings & Fixes

### F1 — source_type not validated (Medium)

**Risk:** Install endpoint accepted arbitrary `source_type` values, enabling
confusion attacks or bypassing source-specific validation.
**Fix:** Whitelist `source_type` to `["local", "github", "registry"]` in
`routes.rs`. Invalid values return 400 error.

### F2 — No manifest size limit (Medium)

**Risk:** Unbounded `manifest_toml` payload could cause OOM/DoS.
**Fix:** 64 KiB hard limit (`MAX_MANIFEST_SIZE`) enforced before parsing.

### F3 — source format not validated for github (Medium)

**Risk:** Malformed GitHub source strings could cause SSRF or confusion.
**Fix:** When `source_type == "github"`, the `source` field is validated
through `github_manifest_url()` which requires `owner/repo` format.

### F4 — Path traversal in install_from_local (High)

**Risk:** `dir_path` parameter with `..` sequences could reference
arbitrary filesystem locations.
**Fix:** Reject any `dir_path` containing `..` with an explicit error.

### F5 — Private IPs in network_allowlist (High)

**Risk:** Manifest `network_allowlist` could include private/loopback
addresses (127.x, 10.x, 192.168.x, localhost, etc.), enabling SSRF
if the daemon enforces the allowlist for outbound requests.
**Fix:** `validate_network_allowlist()` in `manifest.rs` blocks all
RFC 1918, loopback, link-local, and IPv6 private prefixes.

### F6 — README placeholder not replaced (Low)

**Risk:** "CRATE_DESCRIPTION" placeholder left from template.
**Fix:** Replaced with actual crate description.

## Items Confirmed Safe

| Check | Status | Notes |
|-------|--------|-------|
| SQL injection | ✅ Safe | All queries use `rusqlite::params![]` parameterized queries |
| Command injection | ✅ Safe | No subprocess spawning |
| Secret exposure | ✅ Safe | `signing_secret` not persisted; HMAC computed in-memory |
| Race conditions | ✅ Safe | UNIQUE(name,version) constraint prevents duplicate installs |
| Unsafe blocks | ✅ Safe | Zero `unsafe` blocks in crate |
| Auth/AuthZ | ✅ N/A | Handled at daemon level (Extension trait, ring-based MCP) |
| Timing attacks | ✅ Safe | HMAC verification uses constant-time `verify_slice` |

## Test Coverage

- 46 tests (baseline) → 52 tests (+6 security regression tests)
- Path traversal rejection (2 tests)
- Private IP / localhost / loopback allowlist rejection (3 tests)
- Public URL allowlist acceptance (1 test)

## Decision

All findings fixed. No breaking API changes. Security validation is
enforced at parse/install time, before any side effects.

# Security Policy

## Reporting a problem with *this* repository

This repository contains a **proof of concept for an unfixed vulnerability in Apache Log4j**
that is being publicly disclosed here. If you believe you have found a problem with the PoC, the
scanner or the report, please open an issue describing it — the report itself is already public,
so there is nothing left to keep private about the finding.

If you have found a **different** vulnerability in Apache Log4j, please report it to the vendor
rather than here: `security@apache.org`, per
<https://logging.apache.org/security.html>.

## The vulnerabilities this repository documents

| Identifier | Component | Severity | Affected |
|---|---|---|---|
| `LOG4J-SDID-INJECTION` | `org.apache.logging.log4j.core.layout.Rfc5424Layout` (log4j-core) | High | All 2.x and 3.x releases tested; every upstream branch |
| `LOG4J-RFC5424-ATTR-DRIFT` | `Rfc5424Layout` (log4j-core) | Medium–High | 3.0.0-beta2, 3.0.0-beta3, `origin/main` |
| `LOG4J-JSON-NONFINITE` | `log4j-layout-template-json` | Medium | 3.0.0-beta2, 3.0.0-beta3, `origin/main` |

| | |
|---|---|
| **Class** | CWE-117 · CWE-93 · CWE-20 · CWE-1188 · CWE-1330 |
| **Impact** | Integrity — forged syslog records; audit-trail bypass; corrupted log-stream framing |
| **CVE** | None assigned as of 2026-10-23 |
| **Disclosed** | 2026-10-23, in this repository |
| **Vendor notified** | No |

Full analysis: [`README.md`](README.md). Advisories:
[`SECURITY_ADVISORY.md`](SECURITY_ADVISORY.md).

## Disclosure status

This repository **is** the disclosure. It was published on 2026-10-23 with the analysis, the
proof of concept, the raw capture transcripts and a proposed upstream patch.

The Apache Logging Services security team has **not** been contacted, no CVE has been requested,
and no fix is in flight on any upstream branch. That is stated here so a reader can tell the
difference between "a known issue being worked on" and "nobody upstream knows yet" — the latter
is the case, which means deployments are carrying the risk today and the fastest route to a fix
is to forward this to upstream yourself.

If you are able to route it, the vendor contact is `security@apache.org` and the policy is at
<https://logging.apache.org/security.html>.

## PoC safety

The proof of concept binds to `127.0.0.1` only and sends no traffic to any third party. The
`tcp_sink.py` helper is a one-shot localhost listener that writes the raw bytes it receives to
a file.

Do not point the PoC at a production syslog collector, and do not use the payload strings as-is
against any system you are not authorised to test.

## Supported versions

This repository is not a supported Log4j distribution. It documents a defect; it does not fix
one. See [`README.md` §7](README.md#7-remediation) for the proposed upstream patch and the
user-side workarounds.

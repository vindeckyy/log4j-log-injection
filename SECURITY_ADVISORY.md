# Security advisories — Apache Log4j log-integrity defects

> **Three distinct defects, three distinct advisories.** They are documented together here because
> they were found together and share a root theme — a single value silently corrupts the log
> stream — but each is a separate defect, separate in the affected component, in the fix, and in
> what a CVE would cover. Each section below is written in GitHub's draft-advisory structure so
> it can be submitted on its own.
>
> **No CVE has been requested for any of them, and the vendor has not been contacted.**
> See [`README.md` §12](README.md#12-disclosure).
>
> Fields marked `<!-- TODO -->` need to be filled in by the reporter.

**Contents**

1. [LOG4J-SDID-INJECTION — RFC 5424 SD-ID injection](#advisory-1--log4j-sdid-injection--rfc-5424-sd-id-injection)
2. [LOG4J-RFC5424-ATTR-DRIFT — 3.x drops the 2.x `Rfc5424Layout` attribute names](#advisory-2--log4j-rfc5424-attr-drift--3x-drops-the-2-x-rfc5424layout-attribute-names)
3. [LOG4J-JSON-NONFINITE — 3.x `JsonTemplateLayout` emits invalid JSON](#advisory-3--log4j-json-nonfinite--3-x-jsontemplatelayout-emits-invalid-json)

---

## Advisory 1 — `LOG4J-SDID-INJECTION` — RFC 5424 SD-ID injection

### Summary

Log4j's `Rfc5424Layout` writes the RFC 5424 `SD-ID` to the output verbatim — it is neither
character-validated nor newline-escaped — while every other attacker-reachable field in the same
record (the message text, the structured-data parameter names, the parameter values) is
sanitised. An application that places attacker-influenced data in an RFC 5424 SD-ID therefore
lets that data terminate the structured-data element, forge the syslog header fields, and inject
a raw CRLF, appending a fully-formed attacker-authored syslog record to the stream.

### Details

`Rfc5424Layout.formatStructuredElement` appends the SD-ID directly:

```java
// log4j-core 2.26.1, Rfc5424Layout.java
560:        sb.append('[');
561:        sb.append(id);              // <-- SD-ID written verbatim
562:        if (!mdcSdId.toString().equals(id)) {
```

`StructuredDataId` — the class that represents an SD-ID — validates only its **length**:

```java
// log4j-api 2.26.1, StructuredDataId.java
 54:    private static final int MAX_LENGTH = 32;
...
106:            if (name.length() > maxLength) {
107:                throw new IllegalArgumentException(
108:                        String.format("Length of id %s exceeds maximum of %d characters", name, maxLength));
```

RFC 5424 §6.3.3 defines `SD-NAME` — used for both SD-NAME and SD-ID — as printable US-ASCII
**excluding** SPACE, `]`, `=` and `"`. None of that is enforced, and no newline escaping is
applied to the SD-ID.

The defect is a **differential**: in the same method, on the same code path, the MSG is
newline-escaped (`Rfc5424Layout.java:365`), PARAM-NAME is sanitised (`:606`, `:622-646`, `:664`)
and PARAM-VALUE is escaped (`:607`, `:668`). Log4j already contains the exact character-set
predicate the SD-ID needs:

```java
// Rfc5424Layout.java:664-666
private static boolean isParamNameCharacterValid(final char c) {
    return c > 32 && c <= 126 && c != '=' && c != ']' && c != '"';
}
```

### Impact

**Integrity.** Forged syslog records with attacker-chosen PRI, VERSION, TIMESTAMP, HOSTNAME,
APP-NAME, PROCID, MSGID and MSG. This permits audit-trail bypass, evasion of log-based
detection and attribution, and false-alarm generation against SIEM correlation rules. The
genuine record is also truncated at the injected `]` and left malformed.

The `newLineEscape` mitigation introduced for CVE-2026-34478 is **not** effective against this
issue: it is applied to the MSG and the PARAM-VALUE but never to the SD-ID. RFC 5425
octet-counted framing does not contain it either, and the default 32-character limit is not a
control — a complete forged record fits inside it.

### Reproduction

```console
$ git clone <this-repository> && cd log4j-log-injection
$ ./poc/run_poc.sh          # Log4j 2.26.1
$ ./poc/run_poc_3x.sh       # Log4j 3.0.0-beta2 and 3.0.0-beta3
```

Raw bytes captured off a localhost syslog socket:

```
<134>1 2026-10-23T09:04:00.519-04:00 death app 21997 v [x]^M$
<1>1 - evil - - - FORGED@32473] k$
```

A line-oriented collector ingests two events: the application's own record (truncated and
malformed) and a second, complete, attacker-authored record.

### Severity

**High** — integrity impact, comparable in class to CVE-2026-34478 (CVSS 4.0 6.9 MEDIUM) but
broader: it affects every version including those that fixed CVE-2026-34478, it defeats the
mitigation that CVE introduced, and it affects both the 2.x and the 3.x lines.

### Affected versions

| Package | Affected | Patched |
|---|---|---|
| `org.apache.logging.log4j:log4j-core` | `>= 2.0` — all 2.x releases (verified 2.17.1, 2.24.3, 2.26.1) and all 3.x releases (verified 3.0.0-beta2, 3.0.0-beta3) | _none — no fix exists_ |
| `org.apache.logging.log4j:log4j-api` | `>= 2.9.0` — same, both lines | _none — no fix exists_ |
| `org.apache.logging.log4j:log4j-kit` | 3.x only — the 3.x API artifact; same defect (verified 3.0.0-beta3) | _none — no fix exists_ |

Development branches carrying the defect: `origin/2.x` (2.27.0-SNAPSHOT), `origin/2.26.x`
(2.26.2-SNAPSHOT), `origin/2.25.x` (2.25.6-SNAPSHOT) and `origin/main` (3.0.0-SNAPSHOT).

### Workarounds

1. Do not place attacker-influenced data in an SD-ID. Use a fixed, operator-chosen SD-ID and put
   the varying value in a PARAM-NAME/PARAM-VALUE pair, both of which Log4j sanitises.
2. If the SD-ID must be dynamic, pre-sanitise it against `[^\\x21-\\x7E\\[\\]="\\\\]` and keep it
   under 32 characters. Sanitise the enterprise-number half separately, or omit it.
3. Use the default (BSD) `SyslogAppender` format, which routes through `SyslogLayout` and escapes
   newlines across the whole message. `format="RFC5424"` is affected.
4. Downstream: reject records whose structured-data element does not parse, and alert on records
   whose HOSTNAME / APP-NAME / PROCID do not match the sending host.

### Proposed upstream fix

Apply the existing PARAM-NAME character rule to the SD-ID and newline-escape it, in both the 2.x
and the 3.x `Rfc5424Layout`:

```java
private String sanitizeSdId(final String id) {
    if (id == null) {
        return null;
    }
    final StringBuilder sb = new StringBuilder(id.length());
    for (int i = 0; i < id.length(); i++) {
        final char c = id.charAt(i);
        sb.append(isParamNameCharacterValid(c) ? c : '?');
    }
    return escapeNewlines(sb.toString(), escapeNewLine);
}
```

at the sink:

```java
561:        sb.append(sanitizeSdId(id));   // was: sb.append(id);
```

A 2.x-only fix would leave Log4j 3.x exploitable.

### Credit

<!-- TODO: credit the reporter(s) as preferred -->

### References

- Apache Log4j security policy — <https://logging.apache.org/security.html>
- RFC 5424 §6.3.3 (SD-NAME / SD-ID) — <https://www.rfc-editor.org/rfc/rfc5424#section-6.3.3>
- CVE-2026-34478 — the earlier `Rfc5424Layout` log-injection advisory this finding is related to
- Full analysis, evidence and PoC — <https://github.com/vindeckyy/log4j-log-injection>

---

## Advisory 2 — `LOG4J-RFC5424-ATTR-DRIFT` — 3.x drops the 2.x `Rfc5424Layout` attribute names

### Summary

Log4j 2.x accepts two spellings for every `Rfc5424Layout` attribute that controls record framing
and merges them in the builder. Log4j 3.x accepts only one, and which one depends on the
release. A `Rfc5424Layout` element carried over from a 2.x configuration therefore loses its
newline-escaping control on 3.x: the raw newline reaches the collector, and the collector reads
it as a second syslog record.

### Details

```java
// log4j-core/src/main/java/org/apache/logging/log4j/core/layout/Rfc5424Layout.java (rel/2.26.1)
832:        @PluginBuilderAttribute
833:        private boolean newLine;
...
840:        @PluginBuilderAttribute
841:        private boolean includeNL;      // "Same as newLine"
...
848:        @PluginBuilderAttribute
849:        private String newLineEscape;
...
856:        @PluginBuilderAttribute
857:        private String escapeNL;        // "Same as newLineEscape"
...
1174:                    newLine || includeNL,
1175:                    Objects.toString(newLineEscape, escapeNL),
1183:                    Objects.toString(mdcRequired, required),
1186:                    useTlsMessageFormat || useTLSMessageFormat,
```

The 2.x builder's own comments record the intent (`Rfc5424Layout.java:836-838` and `:852-854`):
*"Same as `newLine` … Erroneously introduced in version 2.21.0, but kept for compatibility."*
The 3.x plugin system has no attribute-alias mechanism, so the second spelling is simply gone.

Which spelling survives depends on the release — measured by configuring each attribute on its
own and reading back the startup diagnostics:

| Attribute | 2.26.1 | 3.0.0-beta2 | 3.0.0-beta3 (latest 3.x) | `origin/main` † |
|---|---|---|---|---|
| append the record terminator | `newLine` **or** `includeNL` | `newLine` | `includeNL` | `includeNL` |
| escape newlines in the MSG field | `newLineEscape` **or** `escapeNL` | `newLineEscape` | `escapeNL` | `escapeNL` |
| RFC 5425 octet-counted framing | `useTlsMessageFormat` **or** `useTLSMessageFormat` | both | both | `useTLSMessageFormat` |
| MDC field selection | `mdcExcludes`/`mdcIncludes`/`mdcRequired` **or** `excludes`/`includes`/`required` | `mdc*` | `excludes`/`includes`/`required` | `excludes`/`includes`/`required` |

† read from the 3.x source; the other three columns are measured.

An unknown attribute does not abort the configuration. It is reported once, at startup, and then
ignored:

```
ERROR Rfc5424Layout contains an invalid element or attribute "newLine"
```

The layout is built anyway, with the corresponding control switched off.

### Impact

**Integrity.** One log event whose message contains a newline becomes two syslog records, the
second of which carries attacker-influenced header fields and message body — the same forging
outcome as `LOG4J-SDID-INJECTION`, reached through configuration rather than through a reachable
code path.

It is a silent migration-time failure: one ERROR line during startup is the only signal, and
Log4j does not refuse to start. It also reproduces on the 3.x line the original defect that
CVE-2026-34478 was issued to fix — that fix landed on 2.x in 2.25.4 and was never applicable to
3.x. The MDC attributes fail the same way in the opposite direction: dropping
`mdcExcludes`/`mdcIncludes`/`mdcRequired` means MDC content the operator explicitly excluded
from the record is emitted into it.

### Reproduction

```console
$ git clone <this-repository> && cd log4j-log-injection
$ ./docs/evidence/capture_attr_drift.sh
```

```
--- 3.0.0-beta3  newLine + newLineEscape ---
  startup: ERROR Rfc5424Layout contains invalid attributes "newLine", "newLineEscape"
  repr    : b'... line-one\nline-two'
  records : 2
```

The 2.x configuration on 3.0.0-beta3 emits two syslog records from one log event.

### Severity

**Medium–High.** Same class as CVE-2026-34478 (CVSS 4.0 6.9 MEDIUM) and the same impact as
`LOG4J-SDID-INJECTION`, but it requires a configuration migration rather than a reachable code
path, and it is disclosed by one ERROR line at startup.

### Affected versions

| Package | Affected | Patched |
|---|---|---|
| `org.apache.logging.log4j:log4j-core` | 3.0.0-beta2, 3.0.0-beta3, `origin/main` (3.0.0-SNAPSHOT) — verified | _none — no fix exists_ |
| `org.apache.logging.log4j:log4j-core` | 2.x — **not affected**; both spellings are honoured | — |

### Workarounds

1. On Log4j 3.x use `includeNL="true"`, `escapeNL="&#92;n"`, `useTLSMessageFormat="true"`, and
   `excludes`/`includes`/`required`. Do not copy a 2.x `Rfc5424Layout` element across unchanged.
2. Read the startup log. `contains an invalid element or attribute` means the layout was built
   without the attribute you asked for.
3. Until the configuration is corrected, treat the receiving collector as unable to trust record
   boundaries.

### Proposed upstream fix

Accept both spellings on 3.x, as 2.x does — either by restoring the alias fields and the
`Objects.toString(...)` merges at `Rfc5424Layout.java:1174` and `:1175`, or by extending the
plugin builder with an attribute-alias mechanism.

### Credit

<!-- TODO: credit the reporter(s) as preferred -->

### References

- Apache Log4j security policy — <https://logging.apache.org/security.html>
- CVE-2026-34478 — the advisory this reproduces on the 3.x line
- Full analysis, evidence and PoC — <https://github.com/vindeckyy/log4j-log-injection>

---

## Advisory 3 — `LOG4J-JSON-NONFINITE` — 3.x `JsonTemplateLayout` emits invalid JSON

### Summary

The fix for CVE-2026-34481 — invalid JSON produced by `JsonTemplateLayout` for non-finite
numbers — landed on the 2.x line in 2.25.4 but was never ported to the 3.x line. A
`JsonTemplateLayout` on Log4j 3.x writes a non-finite number as the bare token `NaN`, which is
not valid JSON under RFC 8259.

### Details

```java
// log4j-layout-template-json/.../util/JsonWriter.java — rel/2.26.1, fixed
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

`rel/3.0.0-beta3` is the same. The 3.x `log4j-layout-template-json` module was forked from the
pre-fix code and never received the guard.

### Impact

**Availability and integrity of the log stream.** The emitted record is not valid JSON, so every
strict JSON consumer downstream — Filebeat's JSON decoder, Vector, Fluent Bit's JSON parser, SIEM
ingestion — rejects or truncates it. One event carrying a non-finite number can drop a log line.
Because the token is bare rather than quoted, a crafted value can also terminate or truncate the
surrounding JSON structure.

### Reproduction

```console
$ git clone <this-repository> && cd log4j-log-injection
$ ./docs/evidence/capture_json_nonfinite.sh
```

```
--- 2.26.1 ---
  output : {"message":{"measurement":"NaN","other":1.5}}
  parse  : VALID JSON (RFC 8259)

--- 3.0.0-beta3 ---
  output : {"message":{"measurement":NaN,"other":1.5}}
  parse  : INVALID JSON - non-JSON constant emitted: NaN
```

### Severity

**Medium.** Availability and integrity of the log stream rather than authentication or code
execution — the same severity band as CVE-2026-34481, for the same reason.

### Affected versions

| Package | Affected | Patched |
|---|---|---|
| `org.apache.logging.log4j:log4j-layout-template-json` | 3.0.0-beta2, 3.0.0-beta3, `origin/main` (3.0.0-SNAPSHOT) — verified | _none — no fix exists_ |
| `org.apache.logging.log4j:log4j-layout-template-json` | 2.x — **not affected** since 2.25.4 | 2.25.4, 2.26.0, 2.26.1 |

### Workarounds

1. Do not put non-finite `Double`/`Float` values into log messages, or normalise them before
   logging (`Double.isFinite(v) ? v : 0.0`).
2. Downstream: configure the JSON consumer to tolerate the `NaN`/`Infinity` extension, or to
   drop the affected records with an alert rather than silently.

### Proposed upstream fix

Port the 2.x guard into the 3.x `JsonWriter` — the change is four lines and already exists on
the other branch of the same repository.

### Credit

<!-- TODO: credit the reporter(s) as preferred -->

### References

- Apache Log4j security policy — <https://logging.apache.org/security.html>
- RFC 8259 §6 (JSON numbers) — <https://www.rfc-editor.org/rfc/rfc8259#section-6>
- CVE-2026-34481 — the advisory this reproduces on the 3.x line
- Full analysis, evidence and PoC — <https://github.com/vindeckyy/log4j-log-injection>

---

## Timeline

<!-- TODO: fill in once the vendor has been contacted -->

| Date | Event |
|---|---|
| 2026-10-23 | `LOG4J-SDID-INJECTION` confirmed; live-proven on Log4j 2.17.1, 2.24.3, 2.26.1, 3.0.0-beta2 and 3.0.0-beta3 |
| 2026-10-23 | `LOG4J-RFC5424-ATTR-DRIFT` confirmed; live-proven on Log4j 3.0.0-beta2 and 3.0.0-beta3, with 2.26.1 as the control |
| 2026-10-23 | `LOG4J-JSON-NONFINITE` confirmed; live-proven on Log4j 3.0.0-beta2 and 3.0.0-beta3, with 2.25.3/2.25.4/2.26.1 as the control |
| 2026-10-23 | Public disclosure in this repository — the vendor has not been contacted |
| <!-- TODO --> | Report submitted to `security@apache.org` |
| <!-- TODO --> | Vendor acknowledgement |
| <!-- TODO --> | Fix proposed and reviewed |

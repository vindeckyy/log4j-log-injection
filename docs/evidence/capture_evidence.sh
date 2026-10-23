#!/usr/bin/env bash
#
# Regenerate the raw evidence transcripts in this directory.
#
#   ./capture_evidence.sh
#
# Writes poc-2.x.txt, poc-3.x.txt, scanner-output.txt and the annotated
# source excerpts. Everything runs against 127.0.0.1 only.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC="$(cd "$HERE/../../poc" && pwd)"
LAB="${LAB_DIR:-/tmp/log4j-sdid-evidence}"
VERSION_2X="${LOG4J_VERSION:-2.26.1}"
VERSION_3X="3.0.0-beta2"
VERSION_3X_B3="3.0.0-beta3"
# Log4j 3.x moved the API out of log4j-api into log4j-kit; the 3.x releases
# still consume the 2.x log4j-api for the public logging API.
API_3X="2.24.1"
MVN="https://repo1.maven.org/maven2/org/apache/logging/log4j"

mkdir -p "$LAB/jars2" "$LAB/jars3" "$LAB/jars3b3"
cd "$LAB"

fetch() { # <file> <url>
    [ -f "$1" ] || curl -fsSL --max-time 90 -o "$1" "$2"
}

for a in log4j-api log4j-core; do
    fetch "jars2/$a-$VERSION_2X.jar" \
        "$MVN/$a/$VERSION_2X/$a-$VERSION_2X.jar"
done
for a in log4j-api log4j-core log4j-plugins; do
    fetch "jars3/$a-$VERSION_3X.jar" \
        "$MVN/$a/$VERSION_3X/$a-$VERSION_3X.jar"
done
for a in log4j-kit log4j-core log4j-plugins; do
    fetch "jars3b3/$a-$VERSION_3X_B3.jar" \
        "$MVN/$a/$VERSION_3X_B3/$a-$VERSION_3X_B3.jar"
done
fetch "jars3b3/log4j-api-$API_3X.jar" \
    "$MVN/log4j-api/$API_3X/log4j-api-$API_3X.jar"

cp "$POC/SdIdPoC.java" "$POC/tcp_sink.py" "$LAB/"
cp "$POC/log4j2-rfc5424-sdid.xml" "$LAB/"
# 2.x and 3.x get separate configuration discovery roots on purpose: a stray
# log4j2.xml on the 2.x classpath would let 2.x auto-discover a configuration
# and silently ignore the explicit -Dlog4j.configurationFile below.
cp "$POC/log4j2-syslog-tcp.xml" "$LAB/log4j2-syslog-tcp.xml"   # 2.x: explicit -Dlog4j.configurationFile
mkdir -p "$LAB/out3" "$LAB/out3b3"
cp "$POC/log4j2-syslog-tcp.xml" "$LAB/out3/log4j2.xml"          # 3.x: classpath discovery
# 3.0.0-beta3 renamed the Rfc5424Layout attributes, so it needs its own config
# with the 3.x spellings (includeNL / escapeNL).
cp "$POC/log4j2-syslog-tcp-3x.xml" "$LAB/out3b3/log4j2.xml"
rm -f "$LAB/log4j2.xml"                                         # ...and keep it off the 2.x classpath

CP2="jars2/log4j-api-$VERSION_2X.jar:jars2/log4j-core-$VERSION_2X.jar"
CP3="jars3/log4j-api-$VERSION_3X.jar:jars3/log4j-core-$VERSION_3X.jar:jars3/log4j-plugins-$VERSION_3X.jar"
CP3B3="jars3b3/log4j-kit-$VERSION_3X_B3.jar:jars3b3/log4j-api-$API_3X.jar:jars3b3/log4j-core-$VERSION_3X_B3.jar:jars3b3/log4j-plugins-$VERSION_3X_B3.jar"

javac -proc:none -cp "$CP2" -d . SdIdPoC.java
javac -proc:none -cp "$CP3" -d out3 SdIdPoC.java
javac -proc:none -cp "$CP3B3" -d out3b3 SdIdPoC.java

capture_wire() { # <port> <classpath> <classes-dir> <mode> <outfile>
    local port="$1" cp="$2" cd="$3" mode="$4" out="$5"
    rm -f "$out"
    python3 tcp_sink.py "$port" "$out" 8 > sink.log 2>&1 &
    local sink=$!
    sleep 1.5
    if [ "$cd" = "." ]; then
        # 2.x: explicit configuration file
        java -cp "$cp:$cd" -DsyslogPort="$port" \
            -Dlog4j.configurationFile="$LAB/log4j2-syslog-tcp.xml" \
            SdIdPoC "$mode" >/dev/null 2>&1 || true
    else
        # 3.x: discovers log4j2.xml on the classpath, which sits next to the classes
        java -cp "$cp:$cd" -DsyslogPort="$port" \
            SdIdPoC "$mode" >/dev/null 2>&1 || true
    fi
    sleep 1
    wait "$sink" 2>/dev/null || true
    # A silent zero-byte capture means the configuration was not loaded. Fail loudly
    # instead of shipping an empty transcript as if it were evidence.
    if [ ! -s "$out" ]; then
        echo "ERROR: no bytes captured for mode '$mode' ($out)" >&2
        return 1
    fi
}

show_wire() { # <file>
    python3 - "$1" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
print("    total bytes:", len(d))
print("    repr       :", repr(d))
print()
for i, line in enumerate(d.split(b"\n")):
    if not line.strip():
        continue
    print("    line %d: %r" % (i, line))
    s = line.decode("utf-8", "replace")
    if s.startswith("<"):
        p = s.index(">")
        fields = s[p + 1:].split(" ", 6)
        print("      PRI       :", s[: p + 1])
        for name, val in zip(
            ["VERSION", "TIMESTAMP", "HOSTNAME", "APP-NAME", "PROCID", "MSGID"], fields[:6]
        ):
            print("      %-10s: %s" % (name, val))
        tail = fields[6] if len(fields) > 6 else ""
        sd, _, msg = tail.partition(" ")
        print("      SD        :", sd)
        print("      MSG       :", msg)
PY
}

# ---------------------------------------------------------------- 2.x ------
{
  echo "# Evidence — PoC transcripts, Apache Log4j ${VERSION_2X}"
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
  echo "java: $(java -version 2>&1 | head -1)"
  echo
  echo "Each block is a verbatim terminal capture. The 'wire' sections are the raw"
  echo "bytes a localhost syslog collector received from Log4j."
  echo
  echo "## A. File appender with \`newLineEscape=\"\\\\n\"\` enabled"
  echo
  echo '```'
  for mode in baseline breakout crlf forge32 forgebig einnl; do
    echo "  mode=$mode"
    java -cp "$CP2:." -Dlog4j.configurationFile=log4j2-rfc5424-sdid.xml SdIdPoC "$mode" >/dev/null 2>&1
    sed 's/^/    /' out-sdid.txt | cat -A | sed 's/\$$/<LF>/'
    echo
  done
  echo '```'
  echo
  echo "## B. Network syslog over TCP (RFC 6587, \`SocketAppender\`)"
  echo
  port=5200
  for mode in baseline breakout crlf forge32 forgebig einnl; do
    port=$((port + 1))
    capture_wire "$port" "$CP2" "." "$mode" "wire-$mode.bin"
    echo "### mode \`$mode\`"
    echo
    echo '```'
    show_wire "wire-$mode.bin"
    echo '```'
    echo
  done
} > "$HERE/poc-2.x.txt" 2>&1

# ---------------------------------------------------------------- 3.x ------
{
  echo "# Evidence — PoC transcripts, Apache Log4j ${VERSION_3X}"
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
  echo "java: $(java -version 2>&1 | head -1)"
  echo
  echo "Identical PoC source as the 2.x run; only the Log4j artifacts differ."
  echo
  echo "## A. Log4j ${VERSION_3X} - network syslog over TCP (RFC 6587, \`SocketAppender\`)"
  echo
  port=5300
  for mode in baseline breakout crlf forge32 forgebig einnl; do
    port=$((port + 1))
    capture_wire "$port" "$CP3" "out3" "$mode" "wire3-$mode.bin"
    echo "### mode \`$mode\`"
    echo
    echo '```'
    show_wire "wire3-$mode.bin"
    echo '```'
    echo
  done
  echo "## B. Log4j ${VERSION_3X_B3} - network syslog over TCP, newline escaping ENABLED"
  echo
  echo "The 3.x configuration uses the renamed attributes (\`includeNL\` / \`escapeNL\`)"
  echo "and turns newline escaping ON. The SD-ID still injects a raw CRLF, which"
  echo "shows the bypass is independent of the escaping setting."
  echo
  port=5400
  for mode in baseline breakout crlf forge32 forgebig einnl; do
    port=$((port + 1))
    capture_wire "$port" "$CP3B3" "out3b3" "$mode" "wire3b3-$mode.bin"
    echo "### mode \`$mode\`"
    echo
    echo '```'
    show_wire "wire3b3-$mode.bin"
    echo '```'
    echo
  done
} > "$HERE/poc-3.x.txt" 2>&1

# ------------------------------------------------------------- scanner -----
{
  echo "# Evidence — log4j_audit.py output"
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')."
  echo
  echo "## A. Log4j 2.x artifacts"
  echo
  echo '```'
  python3 "$HERE/../../log4j_audit.py" "$LAB/jars2" 2>&1
  echo '```'
  echo
  echo "## B. Log4j 3.x artifacts"
  echo
  echo '```'
  python3 "$HERE/../../log4j_audit.py" "$LAB/jars3" 2>&1
  echo '```'
  echo
  echo "## C. Log4j 3.0.0-beta3 artifacts"
  echo
  echo '```'
  python3 "$HERE/../../log4j_audit.py" "$LAB/jars3b3" 2>&1
  echo '```'
} > "$HERE/scanner-output.txt" 2>&1

echo "wrote:"
ls -l "$HERE"/poc-2.x.txt "$HERE"/poc-3.x.txt "$HERE"/scanner-output.txt

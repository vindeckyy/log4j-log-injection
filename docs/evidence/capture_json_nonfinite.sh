#!/usr/bin/env bash
#
# Regenerate the evidence for LOG4J-JSON-NONFINITE.
#
#   ./capture_json_nonfinite.sh
#
# Writes poc-json-nonfinite.txt.
#
# The defect: the CVE-2026-34481 fix (a Double/Float.isFinite guard in
# JsonWriter) landed on the 2.x line in 2.25.4 but was never ported to the 3.x
# line. A JsonTemplateLayout that serialises a non-finite number therefore
# writes the bare token NaN, which is not valid JSON (RFC 8259), and every
# strict parser downstream rejects or truncates the record.
#
# Everything runs against the local filesystem only.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC="$(cd "$HERE/../../poc" && pwd)"
LAB="${LAB_DIR:-/tmp/log4j-jsonnan}"
MVN="https://repo1.maven.org/maven2/org/apache/logging/log4j"

mkdir -p "$LAB/jars" "$LAB/cfg" "$LAB/out"
cd "$LAB"

fetch() { # <file> <url>
    [ -f "$1" ] || curl -fsSL --max-time 90 -o "$1" "$2"
}

for v in 2.25.3 2.25.4 2.26.1; do
    for a in log4j-api log4j-core log4j-layout-template-json; do
        fetch "jars/$a-$v.jar" "$MVN/$a/$v/$a-$v.jar"
    done
done
for a in log4j-api log4j-core log4j-plugins log4j-layout-template-json; do
    fetch "jars/$a-3.0.0-beta2.jar" "$MVN/$a/3.0.0-beta2/$a-3.0.0-beta2.jar"
done
fetch "jars/log4j-kit-3.0.0-beta3.jar" "$MVN/log4j-kit/3.0.0-beta3/log4j-kit-3.0.0-beta3.jar"
fetch "jars/log4j-api-2.24.1.jar" "$MVN/log4j-api/2.24.1/log4j-api-2.24.1.jar"
for a in log4j-core log4j-plugins log4j-layout-template-json; do
    fetch "jars/$a-3.0.0-beta3.jar" "$MVN/$a/3.0.0-beta3/$a-3.0.0-beta3.jar"
done

# --- template ---------------------------------------------------------------
# Resolves the event message as an object rather than a string, so the
# Double.NaN in the payload reaches JsonWriter.writeNumber().
cat > EventTemplate.json <<'EOF'
{
  "message": {
    "$resolver": "message",
    "stringified": false
  }
}
EOF

mkcfg() { # <dir>
    mkdir -p "cfg/$1"
    cp EventTemplate.json "cfg/$1/"
    cat > "cfg/$1/log4j2.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="ERROR">
  <Appenders>
    <File name="F" fileName="${sys:outFile}" append="false">
      <JsonTemplateLayout eventTemplateUri="classpath:EventTemplate.json"/>
    </File>
  </Appenders>
  <Loggers><Root level="info"><AppenderRef ref="F"/></Root></Loggers>
</Configuration>
EOF
}
for d in v2_25_3 v2_25_4 v2_26_1 v3_beta2 v3_beta3; do mkcfg "$d"; done

javac -nowarn -cp "jars/log4j-api-3.0.0-beta2.jar:jars/log4j-core-3.0.0-beta2.jar:jars/log4j-plugins-3.0.0-beta2.jar:jars/log4j-layout-template-json-3.0.0-beta2.jar" -d out "$POC/JsonNaNPoC.java"

run() { # <label> <classpath> <cfgdir> <outfile> <version>
    rm -f "out/$4"
    echo "--- $1 ---"
    local combined
    combined="$(java -cp "$2:cfg/$3:out" -DoutFile="out/$4" JsonNaNPoC 2>&1 || true)"
    echo "$combined" | grep -E 'ERROR|WARN|invalid' | sed 's/^/  startup: /' || true
    if [ -s "out/$4" ]; then
        python3 - "out/$4" <<'PY'
import sys, json

d = open(sys.argv[1], 'rb').read()
print("  output :", d.decode('utf-8').strip())

def reject(const):
    raise ValueError("non-JSON constant emitted: " + const)

try:
    json.loads(d.decode('utf-8').strip(), parse_constant=reject)
    print("  parse  : VALID JSON (RFC 8259)")

except Exception as e:
    print("  parse  : INVALID JSON -", e)

pass
PY
        local v
        v="$(python3 - "out/$4" <<'PY'
import sys, json
def reject(c): raise ValueError("non-JSON constant emitted: " + c)
try:
    json.loads(open(sys.argv[1], 'rb').read().decode('utf-8').strip(), parse_constant=reject)
    print("valid")
except Exception:
    print("INVALID")
PY
)"
        printf '| %s | %s |\n' "$5" "$v" >> results.txt
    else
        echo "  (nothing was written)"
        printf '| %s | n/a |\n' "$5" >> results.txt
    fi
    echo
}

: > results.txt

{
  echo "# Evidence — LOG4J-JSON-NONFINITE"
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
  echo "java: $(java -version 2>&1 | head -1)"
  echo
  echo "One log event is written whose message carries a Double.NaN. The layout"
  echo "is a JsonTemplateLayout resolving the message as an object, so the"
  echo "non-finite number reaches JsonWriter.writeNumber(double)."
  echo
  echo "RFC 8259 has no NaN literal. A layout that emits the bare token NaN"
  echo "produces a document that strict JSON parsers reject."
  echo
  echo "## A. Log4j 2.25.3 (before the CVE-2026-34481 fix)"
  echo
  echo '```'
  run "2.25.3" "jars/log4j-api-2.25.3.jar:jars/log4j-core-2.25.3.jar:jars/log4j-layout-template-json-2.25.3.jar" "v2_25_3" "j2_25_3.txt" "2.25.3"
  echo '```'
  echo
  echo "## B. Log4j 2.25.4 (the fix landed here)"
  echo
  echo '```'
  run "2.25.4" "jars/log4j-api-2.25.4.jar:jars/log4j-core-2.25.4.jar:jars/log4j-layout-template-json-2.25.4.jar" "v2_25_4" "j2_25_4.txt" "2.25.4"
  echo '```'
  echo
  echo "## C. Log4j 2.26.1 (latest 2.x release)"
  echo
  echo '```'
  run "2.26.1" "jars/log4j-api-2.26.1.jar:jars/log4j-core-2.26.1.jar:jars/log4j-layout-template-json-2.26.1.jar" "v2_26_1" "j2_26_1.txt" "2.26.1"
  echo '```'
  echo
  echo "## D. Log4j 3.0.0-beta2"
  echo
  echo '```'
  run "3.0.0-beta2" "jars/log4j-api-3.0.0-beta2.jar:jars/log4j-core-3.0.0-beta2.jar:jars/log4j-plugins-3.0.0-beta2.jar:jars/log4j-layout-template-json-3.0.0-beta2.jar" "v3_beta2" "j3_beta2.txt" "3.0.0-beta2"
  echo '```'
  echo
  echo "## E. Log4j 3.0.0-beta3 (latest 3.x release)"
  echo
  echo '```'
  run "3.0.0-beta3" "jars/log4j-kit-3.0.0-beta3.jar:jars/log4j-api-2.24.1.jar:jars/log4j-core-3.0.0-beta3.jar:jars/log4j-plugins-3.0.0-beta3.jar:jars/log4j-layout-template-json-3.0.0-beta3.jar" "v3_beta3" "j3_beta3.txt" "3.0.0-beta3"
  echo '```'
  echo
  echo "## Summary"
  echo
  echo "Generated from the runs above."
  echo
  echo "| Version | Emitted JSON |"
  echo "|---|---|"
  cat results.txt
} > "$HERE/poc-json-nonfinite.txt" 2>&1

echo "wrote:"
ls -l "$HERE/poc-json-nonfinite.txt"

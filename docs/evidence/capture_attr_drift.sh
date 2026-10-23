#!/usr/bin/env bash
#
# Regenerate the evidence for LOG4J-RFC5424-ATTR-DRIFT.
#
#   ./capture_attr_drift.sh
#
# Writes poc-attr-drift.txt.
#
# The defect: Apache Log4j 3.x renamed the Rfc5424Layout builder attributes and
# dropped the canonical 2.x spellings. A 2.x configuration that neutralises
# newlines in the RFC 5424 MSG field therefore loses that control on 3.x: the
# unknown attribute is reported once, at startup, as a configuration ERROR, and
# the layout is then built with newline escaping switched off.
#
# Everything runs against 127.0.0.1 / the local filesystem only.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC="$(cd "$HERE/../../poc" && pwd)"
LAB="${LAB_DIR:-/tmp/log4j-attrdrift}"
MVN="https://repo1.maven.org/maven2/org/apache/logging/log4j"

mkdir -p "$LAB/jars" "$LAB/cfg" "$LAB/out"
cd "$LAB"

fetch() { # <file> <url>
    [ -f "$1" ] || curl -fsSL --max-time 90 -o "$1" "$2"
}

# --- 2.x control ------------------------------------------------------------
for a in log4j-api log4j-core; do
    fetch "jars/$a-2.26.1.jar" "$MVN/$a/2.26.1/$a-2.26.1.jar"
done
# --- 3.0.0-beta2 ------------------------------------------------------------
for a in log4j-api log4j-core log4j-plugins; do
    fetch "jars/$a-3.0.0-beta2.jar" "$MVN/$a/3.0.0-beta2/$a-3.0.0-beta2.jar"
done
# --- 3.0.0-beta3 (the 3.x line moved its API into log4j-kit) -----------------
fetch "jars/log4j-kit-3.0.0-beta3.jar" "$MVN/log4j-kit/3.0.0-beta3/log4j-kit-3.0.0-beta3.jar"
fetch "jars/log4j-api-2.24.1.jar" "$MVN/log4j-api/2.24.1/log4j-api-2.24.1.jar"
for a in log4j-core log4j-plugins; do
    fetch "jars/$a-3.0.0-beta3.jar" "$MVN/$a/3.0.0-beta3/$a-3.0.0-beta3.jar"
done

CP2="jars/log4j-api-2.26.1.jar:jars/log4j-core-2.26.1.jar"
CPB2="jars/log4j-api-3.0.0-beta2.jar:jars/log4j-core-3.0.0-beta2.jar:jars/log4j-plugins-3.0.0-beta2.jar"
CPB3="jars/log4j-kit-3.0.0-beta3.jar:jars/log4j-api-2.24.1.jar:jars/log4j-core-3.0.0-beta3.jar:jars/log4j-plugins-3.0.0-beta3.jar"

# --- configurations ---------------------------------------------------------
# Same layout, same event; only the attribute spelling differs.
# The attribute values use the XML entity &#92; for the backslash, so the
# configuration contains no literal backslash and no shell-escaping hazards.
mkcfg() { # <dir> <attrs>
    mkdir -p "cfg/$1"
    cat > "cfg/$1/log4j2.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="ERROR">
  <Appenders>
    <File name="F" fileName="\${sys:outFile}" append="false">
      <Rfc5424Layout id="default@32473" appName="app" $2/>
    </File>
  </Appenders>
  <Loggers><Root level="info"><AppenderRef ref="F"/></Root></Loggers>
</Configuration>
EOF
}
# The canonical 2.x spellings.
mkcfg "2x-names" 'newLine="true" newLineEscape="&#92;n"'
# The spellings the 3.x builder exposes.
mkcfg "3x-names" 'includeNL="true" escapeNL="&#92;n"'

javac -nowarn -cp "$CPB3" -d out "$POC/AttrDriftPoC.java"

# --- probe every candidate attribute against every version ------------------
# The behavioural question is not "which field exists" but "which spelling does
# this release accept". Each attribute is configured on its own and the startup
# diagnostics are read back.
PROBE_ATTRS='newLine includeNL newLineEscape escapeNL useTlsMessageFormat useTLSMessageFormat mdcExcludes excludes mdcIncludes includes mdcRequired required'

probe_value() { # <attr>
    case "$1" in
        *Escape|*escapeNL) echo '&#92;n' ;;
        *) echo 'true' ;;
    esac
}

probe() { # <label> <classpath> <version>
    echo "--- $1 ---"
    for a in $PROBE_ATTRS; do
        mkdir -p "cfg/probe"
        cat > "cfg/probe/log4j2.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="ERROR">
  <Appenders>
    <File name="F" fileName="\${sys:outFile}" append="false">
      <Rfc5424Layout id="default@32473" appName="app" $a="$(probe_value "$a")"/>
    </File>
  </Appenders>
  <Loggers><Root level="info"><AppenderRef ref="F"/></Root></Loggers>
</Configuration>
EOF
        local combined
        combined="$(java -cp "$2:cfg/probe:out" -DoutFile="out/probe.txt" AttrDriftPoC 2>&1 || true)"
        # Log4j words this two ways: "contains an invalid element or attribute \"X\""
        # for one unknown name, and "contains invalid attributes \"X\", \"Y\"" for
        # several. Either means the attribute was discarded.
        if echo "$combined" | grep -qE 'invalid (element or )?attribute'; then
            printf '  %-22s REJECTED\n' "$a"
            printf '| `%s` | rejected |\n' "$a" >> probe-$3.txt
        elif echo "$combined" | grep -qE 'ERROR.*Rfc5424Layout'; then
            printf '  %-22s rejected (other error)\n' "$a"
            printf '| `%s` | rejected |\n' "$a" >> probe-$3.txt
        else
            printf '  %-22s accepted\n' "$a"
            printf '| `%s` | accepted |\n' "$a" >> probe-$3.txt
        fi
    done
    echo
}

run() { # <label> <classpath> <cfgdir> <outfile> <version> <attr-label>
    rm -f "out/$4"
    echo "--- $1 ---"
    local combined
    combined="$(java -cp "$2:cfg/$3:out" -DoutFile="out/$4" AttrDriftPoC 2>&1 || true)"
    local diag
    diag="$(echo "$combined" | grep -E 'ERROR|WARN|invalid attribute' || true)"
    if [ -n "$diag" ]; then
        echo "$diag" | sed 's/^/  startup: /'
    else
        echo "  startup: (no configuration diagnostics)"
    fi
    if [ -s "out/$4" ]; then
        python3 - "out/$4" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
lines = [l for l in d.split(b'\n') if l.strip()]
print("  bytes   :", len(d))
print("  repr    :", repr(d))
print("  records :", len(lines), "(1 = one syslog record, >1 = the record was split)")
PY
        # Record the verdict for the generated summary table.
        local n
        n="$(python3 -c "
import sys
d=open('out/$4','rb').read()
print(len([l for l in d.split(b'\n') if l.strip()]))
")"
        local esc
        if [ "$n" = "1" ]; then esc="yes"; else esc="**no**"; fi
        printf '| %s | `%s` | %s | %s |\n' "$5" "$6" "$esc" "$n" >> results.txt
    else
        echo "  (nothing was written)"
        printf '| %s | `%s` | n/a | 0 |\n' "$5" "$6" >> results.txt
    fi
    echo
}

: > results.txt
: > probe-2.26.1.txt
: > probe-3.0.0-beta2.txt
: > probe-3.0.0-beta3.txt

{
  echo "# Evidence — LOG4J-RFC5424-ATTR-DRIFT"
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
  echo "java: $(java -version 2>&1 | head -1)"
  echo
  echo "One log event is written whose message contains an embedded newline. The"
  echo "only variable between runs is which Rfc5424Layout attributes the"
  echo "configuration uses."
  echo
  echo "  2.x spellings : newLine=\"true\" newLineEscape=\"&#92;n\""
  echo "  3.x spellings : includeNL=\"true\" escapeNL=\"&#92;n\""
  echo
  echo "A correctly configured layout emits ONE syslog record with the newline"
  echo "escaped. A layout whose newline-escape attribute was silently discarded"
  echo "emits the newline raw, and the collector sees TWO records."
  echo
  echo "## A. Log4j 2.26.1 (control — both spellings are honoured)"
  echo
  echo '```'
  run "2.26.1  newLine + newLineEscape" "$CP2" "2x-names" "r2-2xnames.txt" "2.26.1" 'newLine` + `newLineEscape'
  run "2.26.1  includeNL + escapeNL"   "$CP2" "3x-names" "r2-3xnames.txt" "2.26.1" 'includeNL` + `escapeNL'
  echo '```'
  echo
  echo "## B. Log4j 3.0.0-beta2"
  echo
  echo '```'
  run "beta2   newLine + newLineEscape" "$CPB2" "2x-names" "rb2-2xnames.txt" "3.0.0-beta2" 'newLine` + `newLineEscape'
  run "beta2   includeNL + escapeNL"   "$CPB2" "3x-names" "rb2-3xnames.txt" "3.0.0-beta2" 'includeNL` + `escapeNL'
  echo '```'
  echo
  echo "## C. Log4j 3.0.0-beta3 (latest 3.x release)"
  echo
  echo '```'
  run "beta3   newLine + newLineEscape" "$CPB3" "2x-names" "rb3-2xnames.txt" "3.0.0-beta3" 'newLine` + `newLineEscape'
  run "beta3   includeNL + escapeNL"   "$CPB3" "3x-names" "rb3-3xnames.txt" "3.0.0-beta3" 'includeNL` + `escapeNL'
  echo '```'
  echo
  echo "## D. Which attribute spellings each release accepts"
  echo
  echo "Each attribute is configured on its own and the startup diagnostics are"
  echo "read back. \"rejected\" means the layout was built without that"
  echo "attribute — which is the defect, because the configuration asks for it."
  echo
  echo "### Log4j 2.26.1"
  echo
  echo '```'
  probe "2.26.1" "$CP2" "2.26.1"
  echo '```'
  echo
  echo "### Log4j 3.0.0-beta2"
  echo
  echo '```'
  probe "3.0.0-beta2" "$CPB2" "3.0.0-beta2"
  echo '```'
  echo
  echo "### Log4j 3.0.0-beta3"
  echo
  echo '```'
  probe "3.0.0-beta3" "$CPB3" "3.0.0-beta3"
  echo '```'
  echo
  echo "### Side by side"
  echo
  python3 - probe-2.26.1.txt probe-3.0.0-beta2.txt probe-3.0.0-beta3.txt <<'PY'
import sys

def load(path):
    out = {}
    for line in open(path):
        line = line.strip()
        if line.startswith('|') and line.endswith('|'):
            parts = [p.strip() for p in line.strip('|').split('|')]
            if len(parts) == 2:
                out[parts[0]] = parts[1]
    return out

tables = [load(p) for p in sys.argv[1:]]
names = list(tables[0].keys())
print("| Attribute | " + " | ".join(p.split('-', 1)[1].rsplit('.txt', 1)[0]
                                      for p in sys.argv[1:]) + " |")
print("|---" * (len(tables) + 1) + "|")
for n in names:
    cells = []
    for t in tables:
        v = t.get(n, "?")
        cells.append("**rejected**" if v.startswith("rejected") else v)
    print("| " + n + " | " + " | ".join(cells) + " |")
PY
  echo
  echo "## Summary"
  echo
  echo "Generated from the runs above; \"records\" is the number of syslog records"
  echo "a collector would parse out of the emitted bytes."
  echo
  echo "| Version | Attribute spelling | Newline escaped | Records emitted |"
  echo "|---|---|---|---|"
  cat results.txt
} > "$HERE/poc-attr-drift.txt" 2>&1

echo "wrote:"
ls -l "$HERE/poc-attr-drift.txt"

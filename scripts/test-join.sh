#!/usr/bin/env bash
# Exercise the actual served bootstrap with deterministic download/installer
# fixtures. Run only in a fresh disposable container (see Fork CI).
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 && ! -e /usr/local/bin/eztunnel && ! -L /usr/local/bin/eztunnel ]] ||
    { echo 'Run the join test in a clean disposable Docker container as root.' >&2; exit 2; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
join=$here/../src/dashboard/join.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"; rm -f -- /usr/local/bin/eztunnel' EXIT
mkdir "$work/bin"
export MOCK_DIR=$work MOCK_TRACE=$work/trace
export PATH="$work/bin:$PATH"
cat > "$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -eu
printf 'download\n' >> "$MOCK_TRACE"
if [[ $MOCK_CASE == download-fail ]]; then
    echo 'curl: simulated download failure' >&2
    exit 7
fi
out=
while (( $# )); do
    case $1 in
        -o) out=$2; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n $out ]]
cp "$MOCK_DIR/installer" "$out"
MOCK
cat > "$work/installer" <<'MOCK'
#!/usr/bin/env bash
set -eu
prefix=/usr/local
version=latest
menu=1
while (( $# )); do
    case $1 in
        --prefix) prefix=$2; shift 2 ;;
        --version) version=$2; shift 2 ;;
        --no-menu) menu=0; shift ;;
        *) exit 9 ;;
    esac
done
[[ $menu == 0 ]] || { echo 'Unexpected installer menu' >&2; exit 9; }
if [[ $prefix != /usr/local ]]; then
    printf 'stage %s\n' "$version" >> "$MOCK_TRACE"
    [[ $version == latest ]]
    if [[ $MOCK_CASE == stage-fail || $MOCK_CASE == legacy-stage-fail ]]; then
        echo 'GLIBC_2.39 not found (simulated loader error)' >&2
        exit 1
    fi
else
    printf 'install %s\n' "$version" >> "$MOCK_TRACE"
    [[ $version == v0.13.0-ach.99 ]] || { echo 'Must install the checked version' >&2; exit 9; }
fi
mkdir -p "$prefix/bin"
cp "$MOCK_DIR/program" "$prefix/bin/eztunnel"
chmod 755 "$prefix/bin/eztunnel"
# The real installer can fail when restarting a management service AFTER
# replacing the executable. Leave a usable agent in this partial-install case.
if [[ $prefix == /usr/local && $MOCK_CASE == install-fail ]]; then
    echo 'simulated management-service restart failure after installation' >&2
    exit 1
fi
MOCK
cat > "$work/program" <<'MOCK'
#!/usr/bin/env bash
set -eu
case "$*" in
    --version) echo 'eztunnel 0.13.0-ach.99' ;;
    'agent --help')
        if [[ $MOCK_CASE == no-agent ]]; then
            echo 'agent command unavailable' >&2
            exit 1
        fi
        echo 'join'
        ;;
    'agent join ezj1-test-only')
        printf 'join\n' >> "$MOCK_TRACE"
        if [[ $MOCK_CASE == join-fail ]]; then
            echo 'simulated join rejection' >&2
            exit 3
        fi
        ;;
    *) exit 9 ;;
esac
MOCK
cat > "$work/legacy" <<'MOCK'
#!/usr/bin/env bash
if [[ $1 == --version ]]; then echo 'eztunnel 0.12.0'; exit 0; fi
echo 'agent command unavailable on legacy program' >&2
exit 1
MOCK
chmod 755 "$work/bin/curl" "$work/program" "$work/legacy"
assert_trace() {
    local expected=$1 actual
    actual=$(cat "$MOCK_TRACE")
    if [[ $actual != "$expected" ]]; then
        printf 'Unexpected side effects in %s\nExpected trace:\n%s\nActual trace:\n%s\n' "$MOCK_CASE" "$expected" "$actual" >&2
        exit 1
    fi
}
# Prove the assertion itself fails closed even when its exit status is
# being tested by an if statement (where Bash suppresses errexit).
for forbidden in 'install v0.13.0-ach.99' 'join'; do
    export MOCK_CASE=trace-assertion
    printf 'download\nstage latest\n%s\n' "$forbidden" > "$MOCK_TRACE"
    if (assert_trace $'download\nstage latest') >"$work/assertion.out" 2>&1; then
        echo "Trace assertion accepted prohibited side effect: $forbidden" >&2
        exit 1
    fi
    grep -Fq 'Unexpected side effects' "$work/assertion.out"
done
echo 'PASS: negative trace assertions reject unexpected installation and enrollment'
scenario() {
    export MOCK_CASE=$1
    local expected=$2
    rm -f -- /usr/local/bin/eztunnel
    : > "$MOCK_TRACE"
    if [[ $MOCK_CASE == existing ]]; then
        cp "$work/program" /usr/local/bin/eztunnel
    elif [[ $MOCK_CASE == legacy-* ]]; then
        cp "$work/legacy" /usr/local/bin/eztunnel
    fi
    local rc=0
    bash "$join" ezj1-test-only >"$work/$MOCK_CASE.out" 2>&1 </dev/null || rc=$?
    if [[ $rc != "$expected" ]]; then
        cat "$work/$MOCK_CASE.out" >&2
        echo "Unexpected exit $rc in $MOCK_CASE (expected $expected)" >&2
        exit 1
    fi
    if compgen -G '/root/.eztunnel-join.*' >/dev/null; then
        echo "Join staging directory leaked in $MOCK_CASE" >&2
        exit 1
    fi
    echo "PASS: $MOCK_CASE"
}
scenario existing 0
assert_trace join
scenario download-fail 1
grep -Fq 'curl: simulated download failure' "$work/download-fail.out"
grep -Fq 'Could not download the EZTunnel installer' "$work/download-fail.out"
assert_trace download
[[ ! -e /usr/local/bin/eztunnel ]]
scenario stage-fail 1
grep -Fq 'GLIBC_2.39 not found' "$work/stage-fail.out"
grep -Fq 'Could not prepare a runnable EZTunnel release' "$work/stage-fail.out"
assert_trace $'download\nstage latest'
[[ ! -e /usr/local/bin/eztunnel ]]
scenario legacy-stage-fail 1
grep -Fq 'GLIBC_2.39 not found' "$work/legacy-stage-fail.out"
assert_trace $'download\nstage latest'
cmp "$work/legacy" /usr/local/bin/eztunnel
scenario legacy-upgrade 0
grep -Fq 'This server has eztunnel 0.12.0' "$work/legacy-upgrade.out"
assert_trace $'download\nstage latest\ninstall v0.13.0-ach.99\njoin'
scenario no-agent 1
grep -Fq 'agent command unavailable' "$work/no-agent.out"
grep -Fq 'cannot join a dashboard' "$work/no-agent.out"
assert_trace $'download\nstage latest'
[[ ! -e /usr/local/bin/eztunnel ]]
scenario install-fail 1
grep -Fq 'simulated management-service restart failure after installation' "$work/install-fail.out"
grep -Fq 'Join was not attempted' "$work/install-fail.out"
assert_trace $'download\nstage latest\ninstall v0.13.0-ach.99'
cmp "$work/program" /usr/local/bin/eztunnel
[[ $(/usr/local/bin/eztunnel --version) == 'eztunnel 0.13.0-ach.99' ]]
agent_help=$(/usr/local/bin/eztunnel agent --help)
grep -Fq join <<<"$agent_help"
# Help/version checks above must not consume the enrollment or add side effects.
assert_trace $'download\nstage latest\ninstall v0.13.0-ach.99'
scenario fresh 0
assert_trace $'download\nstage latest\ninstall v0.13.0-ach.99\njoin'
scenario join-fail 3
grep -Fq 'simulated join rejection' "$work/join-fail.out"
assert_trace $'download\nstage latest\ninstall v0.13.0-ach.99\njoin'
echo 'PASS: join diagnostics, staging cleanup, existing agent path, pinned installation, and rejection propagation.'

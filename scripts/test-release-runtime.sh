#!/usr/bin/env bash
# Install and run the exact full-featured release executable on clean userspaces.
# The release is not published yet, so curl serves a local checksum/archive fixture
# with the real asset names; the real installer performs all verification/staging.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: test-release-runtime.sh BINARY VERSION' >&2; exit 2; }
binary=$(realpath "$1")
version=$2
[[ -x $binary ]]
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo 'Unsupported test architecture' >&2; exit 2 ;;
esac
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin" "$work/eztunnel-linux/bin"
install -m 755 "$binary" "$work/eztunnel-linux/bin/eztunnel"
asset="eztunnel-linux-$arch.tar.gz"
tar -czf "$work/$asset" -C "$work" eztunnel-linux
(cd "$work" && sha256sum "$asset" > SHA256SUMS)
sha256sum "$binary" | awk '{print $1}' > "$work/binary.sha256"
cp "$here/install-latest.sh" "$work/install-latest.sh"
cat > "$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
out=
url=
while (( $# )); do
    case "$1" in
        --output) out=$2; shift 2 ;;
        https://*) url=$1; shift ;;
        *) shift ;;
    esac
done
base="https://github.com/ach1992/EZTunnel/releases/download/v$FIXTURE_VERSION/"
[[ -n $out && $url == "$base"* ]]
file=${url#"$base"}
case "$file" in
    SHA256SUMS|eztunnel-linux-x86_64.tar.gz|eztunnel-linux-aarch64.tar.gz)
        cp "/fixture/$file" "$out" ;;
    *) echo "Unexpected fixture request" >&2; exit 1 ;;
esac
MOCK
chmod 755 "$work/bin/curl"
for image in ubuntu:22.04 debian:12 ubuntu:24.04 debian:13; do
    echo "Testing $image ($(uname -m))"
    docker run --rm --network none \
        --mount "type=bind,source=$work,target=/fixture,readonly" \
        -e "FIXTURE_VERSION=$version" "$image" sh -ec '
            getconf GNU_LIBC_VERSION
            export PATH="/fixture/bin:$PATH"
            bash /fixture/install-latest.sh --version "v$FIXTURE_VERSION" --no-menu
            echo "$(cat /fixture/binary.sha256)  /usr/local/bin/eztunnel" | sha256sum -c -
            test "$(/usr/local/bin/eztunnel --version)" = "eztunnel $FIXTURE_VERSION"
            agent_help=$(/usr/local/bin/eztunnel agent --help)
            printf "%s\n" "$agent_help" | grep -q join
            dashboard_help=$(/usr/local/bin/eztunnel dashboard --help)
            printf "%s\n" "$dashboard_help" | grep -q serve
        '
done

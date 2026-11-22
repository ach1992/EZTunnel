#!/usr/bin/env bash
# Isolated, rootless regression test for the exact post-install restart path.
# Do not replace /usr/local/bin/eztunnel or interact with real systemd.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
installer=$here/install-latest.sh
function_body=$(sed -n '/^restart_management_services() {/,/^}/p' "$installer")
post_install=$(sed -n '/^restart_failed=0$/,/^menu_command=/p' "$installer" | sed '$d')
[[ $function_body == *'restart_management_services() {'* ]] || { echo 'Missing installer restart function' >&2; exit 1; }
[[ $post_install == *'restart_management_services || restart_failed=1'* ]] || { echo 'Missing failure propagation' >&2; exit 1; }
[[ $post_install == *'die "EZTunnel $new_version was installed'* ]] || { echo 'Missing partial-success terminal error' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Evaluate only the checked-in function and the post-install call site. The
# earlier installer stages/downloads nothing under this test, and systemctl
# is replaced by a function recording every invocation.
scenario() (
  local name=$1
  local trace=$2
  new_version=0.13.0-ach.1
  old_version=0.12.0-ach.1
  destination=/usr/local/bin
  [[ $name != fresh-install ]] || old_version=''
  [[ $name != custom-prefix ]] || destination=$work/custom-prefix/bin
  c_dim='' c_reset=''
  ok() { printf 'SUCCESS: %s\n' "$*" >&2; }
  note() { printf 'NOTE: %s\n' "$*" >&2; }
  rule() { :; }
  die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
  systemctl() {
    printf '%s\n' "$*" >> "$trace"
    case $1 in
      is-active)
        if [[ $name == inactive ]]; then
          return 3
        fi
        if [[ $name == agent-inactive && $3 == eztunnel-agent.service ]]; then
          return 3
        fi
        return 0
        ;;
      restart)
        case "$name:$2" in
          fail-dashboard:eztunnel-dashboard.service|fail-both:eztunnel-dashboard.service)
            echo 'simulated systemctl dashboard failure' >&2; return 7 ;;
          fail-agent:eztunnel-agent.service|fail-both:eztunnel-agent.service)
            echo 'simulated systemctl agent failure' >&2; return 23 ;;
        esac
        return 0
        ;;
      *)
        echo "Unexpected systemctl invocation: $*" >&2
        return 99
        ;;
    esac
  }
  eval "$function_body"
  eval "$post_install"
)
expect_success() {
  local name=$1
  : > "$work/$name.trace"
  if ! scenario "$name" "$work/$name.trace" >"$work/$name.out" 2>&1; then
    cat "$work/$name.out" >&2
    echo "Unexpected failure in scenario $name" >&2
    exit 1
  fi
}
expect_failure() {
  local name=$1
  : > "$work/$name.trace"
  if scenario "$name" "$work/$name.trace" >"$work/$name.out" 2>&1; then
    echo "Expected failed restart to return nonzero in scenario $name" >&2
    exit 1
  fi
  grep -Fq 'was installed at /usr/local/bin/eztunnel and the previous executable was kept' "$work/$name.out"
  grep -Fq 'an active management service failed to restart' "$work/$name.out"
}
assert_no_tunnel_restart() {
  local name=$1
  if grep '^restart ' "$work/$name.trace" | grep -v -e '^restart eztunnel-dashboard.service$' -e '^restart eztunnel-agent.service$'; then
    echo "Installer restarted a tunnel or an unknown service in $name" >&2
    exit 1
  fi
}

expect_success inactive
! grep -q '^restart ' "$work/inactive.trace"
! grep -q '^SUCCESS:' "$work/inactive.out"
assert_no_tunnel_restart inactive

expect_success fresh-install
! grep -q '^restart ' "$work/fresh-install.trace"
assert_no_tunnel_restart fresh-install

expect_success custom-prefix
! grep -q '^restart ' "$work/custom-prefix.trace"
assert_no_tunnel_restart custom-prefix

expect_success both-ok
grep -Fq 'restart eztunnel-dashboard.service' "$work/both-ok.trace"
grep -Fq 'restart eztunnel-agent.service' "$work/both-ok.trace"
grep -Fq 'SUCCESS: Restarted eztunnel-dashboard so it runs 0.13.0-ach.1' "$work/both-ok.out"
grep -Fq 'SUCCESS: Restarted eztunnel-agent so it runs 0.13.0-ach.1' "$work/both-ok.out"
assert_no_tunnel_restart both-ok

expect_success agent-inactive
grep -Fq 'restart eztunnel-dashboard.service' "$work/agent-inactive.trace"
! grep -Fq 'restart eztunnel-agent.service' "$work/agent-inactive.trace"
assert_no_tunnel_restart agent-inactive

expect_failure fail-dashboard
grep -Fq 'simulated systemctl dashboard failure' "$work/fail-dashboard.out"
grep -Fq 'Failed to restart eztunnel-dashboard.service (systemctl exit 7)' "$work/fail-dashboard.out"
grep -Fq 'sudo systemctl status eztunnel-dashboard.service --no-pager' "$work/fail-dashboard.out"
grep -Fq 'sudo journalctl -u eztunnel-dashboard.service -n 50 --no-pager' "$work/fail-dashboard.out"
grep -Fq 'sudo systemctl restart eztunnel-dashboard.service' "$work/fail-dashboard.out"
grep -Fq 'restart eztunnel-agent.service' "$work/fail-dashboard.trace"
assert_no_tunnel_restart fail-dashboard

expect_failure fail-agent
grep -Fq 'SUCCESS: Restarted eztunnel-dashboard' "$work/fail-agent.out"
grep -Fq 'simulated systemctl agent failure' "$work/fail-agent.out"
grep -Fq 'Failed to restart eztunnel-agent.service (systemctl exit 23)' "$work/fail-agent.out"
grep -Fq 'sudo systemctl restart eztunnel-agent.service' "$work/fail-agent.out"
assert_no_tunnel_restart fail-agent

expect_failure fail-both
grep -Fq 'Failed to restart eztunnel-dashboard.service (systemctl exit 7)' "$work/fail-both.out"
grep -Fq 'Failed to restart eztunnel-agent.service (systemctl exit 23)' "$work/fail-both.out"
assert_no_tunnel_restart fail-both

echo 'PASS: eight rootless installer post-install scenarios (inactive, fresh, custom prefix, success, mixed, two single failures, both failures); no tunnel restarts.'

#!/usr/bin/env bash
# Step 3 prompt Part E4: runs the same integration suite as
# .github/workflows/ci.yml's "integration" job, but on a real RHEL 9
# host/VM instead of ubuntu-24.04, so the kernel/SELinux/usrmerge facts
# internal/hostprobe and internal/tetra's socket verification depend on are
# exercised against the actual target distribution, not an approximation.
#
# Prerequisites (documented, not automated by this script):
#   - A RHEL 9.x host or VM, SELinux enforcing (architecture doc 9.2),
#     usrmerge intact (the RHEL 9 default).
#   - Root or passwordless sudo for the steps that need it (installing
#     Tetragon, creating the tetragon-relay group, starting/stopping the
#     Tetragon daemon). The test binary itself (`go test`) is run as an
#     unprivileged user in the tetragon-relay group, matching
#     .github/workflows/ci.yml's own separation of privilege.
#   - Go ${GO_VERSION:-1.27.4}+ installed.
#   - Outbound network access to download the pinned Tetragon release
#     tarball (or pre-stage it and set TETRAGON_TARBALL to a local path).
#
# This script has NOT been executed as part of this project's work so far
# (no RHEL 9 host/VM was available in the development environment used to
# write it); see docs/reports/step-03.md section 13. Running it and
# recording the kernel version/outcome is an explicit remaining action item
# for whoever has RHEL 9 hardware/VM access.
set -euo pipefail

TETRAGON_VERSION="${TETRAGON_VERSION:-v1.8.0}"
TETRAGON_TARBALL_SHA256="${TETRAGON_TARBALL_SHA256:?set TETRAGON_TARBALL_SHA256 to the pinned release tarball hash (see .github/workflows/ci.yml)}"
RELAY_GROUP="${RELAY_GROUP:-tetragon-relay}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

echo "== kernel / distribution =="
uname -a
cat /etc/redhat-release 2>/dev/null || echo "WARNING: /etc/redhat-release not found; is this really RHEL 9?"
getenforce 2>/dev/null || echo "WARNING: getenforce not found; cannot confirm SELinux mode"

echo "== downloading Tetragon ${TETRAGON_VERSION} =="
TARBALL="${TETRAGON_TARBALL:-${WORKDIR}/tetragon.tar.gz}"
if [ ! -f "${TARBALL}" ]; then
  curl -fsSL -o "${TARBALL}" \
    "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-amd64.tar.gz"
fi
echo "${TETRAGON_TARBALL_SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${WORKDIR}"
TETRAGON_BIN="$(find "${WORKDIR}" -maxdepth 6 -type f -name tetragon | head -1)"
if [ -z "${TETRAGON_BIN}" ]; then
  echo "could not find the tetragon binary inside the extracted tarball" >&2
  exit 1
fi
chmod +x "${TETRAGON_BIN}"

echo "== preparing relay group and directories =="
sudo groupadd -f "${RELAY_GROUP}"
sudo mkdir -p /var/run/tetragon /etc/tetragon/tetragon.tp.d/relay
# internal/apply.PersistDir creates its atomic-swap temp directory as a
# SIBLING of the target "relay" dir (inside tetragon.tp.d itself), so
# tetragon.tp.d's own permissions must allow the relay group to create
# entries there too, not only inside the "relay" subdirectory.
sudo chown root:"${RELAY_GROUP}" /var/run/tetragon /etc/tetragon/tetragon.tp.d /etc/tetragon/tetragon.tp.d/relay
sudo chmod 2770 /etc/tetragon/tetragon.tp.d /etc/tetragon/tetragon.tp.d/relay
sudo usermod -a -G "${RELAY_GROUP}" "$(id -un)"

echo "== running capability probe (relay-probe --report) =="
GOOS=linux go build -o "${WORKDIR}/relay-probe" ./cmd/relay-probe
sudo "${WORKDIR}/relay-probe" --report --tetragon-binary "${TETRAGON_BIN}" | tee "${WORKDIR}/host-facts-report.json"
echo "Record ${WORKDIR}/host-facts-report.json alongside this run's kernel version in docs/runbooks/capability-matrix.md."

echo "== starting Tetragon (transient unit tetragon.service) =="
# step-03a-review.md R3-1: a real systemd unit, not a bare backgrounded
# process, so internal/tetra's cgroup v2 membership check has a real
# "system.slice/tetragon.service" cgroup to verify against (the same path
# Config.UnitCgroupPath defaults to).
#
# The release tarball mirrors an FHS tree (usr/local/{bin,lib}/...);
# --bpf-lib defaults to /var/lib/tetragon, which only install.sh (not run
# by this script) would populate, so point it at the extracted
# usr/local/lib/tetragon directory directly instead.
BPF_LIB_DIR="$(dirname "${TETRAGON_BIN}")/../lib/tetragon/bpf"
sudo systemd-run --unit=tetragon --collect \
  --property=Type=simple \
  "${TETRAGON_BIN}" \
  --server-address unix:///var/run/tetragon/tetragon.sock \
  --tracing-policy-dir /etc/tetragon/tetragon.tp.d \
  --bpf-lib "${BPF_LIB_DIR}"
cleanup_tetragon() { sudo systemctl stop tetragon.service 2>/dev/null || true; }
trap cleanup_tetragon EXIT
sleep 3
if ! sudo systemctl is-active --quiet tetragon.service; then
  echo "Tetragon did not start; log:" >&2
  sudo journalctl -u tetragon.service --no-pager >&2
  exit 1
fi

echo "== running integration test suite (unprivileged, group ${RELAY_GROUP}) =="
# go test compiles a fresh temp binary per invocation: build real test
# binaries first (no setcap needed since R3-1: the peer checks need no
# capability) and run them directly. `sg` starts a subshell with
# RELAY_GROUP as a supplementary group without requiring a fresh login,
# matching how the systemd unit's own SupplementaryGroups= works in
# production.
go test -tags integration -race -count=1 -c -o "${WORKDIR}/tetra.itest" ./internal/tetra
go test -tags integration -race -count=1 -c -o "${WORKDIR}/apply.itest" ./internal/apply
# TestAllowlist_NoOtherRPCsReferenced (internal/tetra) reads its own
# package's .go files via a relative path, so each compiled test binary
# must run with its source package directory as the working directory.
#
# Unlike .github/workflows/ci.yml's job, this script runs on a real
# RHEL 9 host with SELinux enforcing (architecture doc 9.2), so this is
# the only place internal/tetra's SO_PEERSEC peer check is exercised for
# real with SELinux actually enabled, not merely its selinux_required=false
# disabled-SELinux fallback path.
REPO_ROOT="$(pwd)"
sg "${RELAY_GROUP}" -c "cd '${REPO_ROOT}/internal/tetra' && '${WORKDIR}/tetra.itest' -test.v && cd '${REPO_ROOT}/internal/apply' && '${WORKDIR}/apply.itest' -test.v"

echo "== done =="
echo "Record this run's kernel version (uname -r above), scenario pass/fail,"
echo "and whether it was actually executed (vs. authored-but-unrun) in"
echo "docs/reports/step-03.md section 13."

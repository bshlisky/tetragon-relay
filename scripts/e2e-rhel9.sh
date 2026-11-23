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
sudo chown root:"${RELAY_GROUP}" /var/run/tetragon /etc/tetragon/tetragon.tp.d/relay
sudo chmod 2770 /etc/tetragon/tetragon.tp.d/relay
sudo usermod -a -G "${RELAY_GROUP}" "$(id -un)"

echo "== running capability probe (relay-probe --report) =="
GOOS=linux go build -o "${WORKDIR}/relay-probe" ./cmd/relay-probe
sudo "${WORKDIR}/relay-probe" --report --tetragon-binary "${TETRAGON_BIN}" | tee "${WORKDIR}/host-facts-report.json"
echo "Record ${WORKDIR}/host-facts-report.json alongside this run's kernel version in docs/runbooks/capability-matrix.md."

echo "== starting Tetragon =="
# The release tarball mirrors an FHS tree (usr/local/{bin,lib}/...);
# --bpf-lib defaults to /var/lib/tetragon, which only install.sh (not run
# by this script) would populate, so point it at the extracted
# usr/local/lib/tetragon directory directly instead.
BPF_LIB_DIR="$(dirname "${TETRAGON_BIN}")/../lib/tetragon"
sudo "${TETRAGON_BIN}" \
  --server-address unix:///var/run/tetragon/tetragon.sock \
  --tracing-policy-dir /etc/tetragon/tetragon.tp.d \
  --bpf-lib "${BPF_LIB_DIR}" &
TETRAGON_PID=$!
cleanup_tetragon() { sudo kill "${TETRAGON_PID}" 2>/dev/null || true; }
trap cleanup_tetragon EXIT
sleep 3

echo "== running integration test suite (unprivileged, group ${RELAY_GROUP}) =="
# `sg` starts a subshell with RELAY_GROUP as a supplementary group without
# requiring a fresh login, matching how the systemd unit's own
# SupplementaryGroups= works in production.
sg "${RELAY_GROUP}" -c "go test -tags integration -race -count=1 -v ./internal/tetra/... ./internal/apply/..."

echo "== done =="
echo "Record this run's kernel version (uname -r above), scenario pass/fail,"
echo "and whether it was actually executed (vs. authored-but-unrun) in"
echo "docs/reports/step-03.md section 13."

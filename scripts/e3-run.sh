#!/usr/bin/env bash
# docs/prompts/step-06a-e3-prompt.md: runs relayd as a real process under
# the production systemd unit's sandbox settings, against a real Tetragon
# and the E3 test controller (cmd/e3controller), for every one of S1-S6.
#
# Run by .github/workflows/ci.yml's "e3" job on ubuntu-24.04, after that
# job has: installed swtpm, downloaded/started a real Tetragon as a
# transient systemd unit (the same steps the "integration" job already
# uses), and built every binary this script invokes (relayd twice -- once
# with no build tags, once with -tags testca,testtpm -- plus
# cmd/testenroll, cmd/e3root, cmd/e3controller, cmd/e3tetra, all with
# their own required tags). REPO_ROOT, BIN_DIR and TETRAGON_BIN must be
# set in the environment; see the "e3" job for the exact values.
#
# Every scenario runs regardless of an earlier one's outcome (so a single,
# ~15-20 minute CI round trip shows every scenario's result, not just the
# first failure); this script's own exit code is non-zero if any scenario
# failed. Each scenario function prints "E3 RESULT: <name> PASS|FAIL" as
# its own last line, grepped by the job summary step.
set -uo pipefail
set -x

: "${REPO_ROOT:?}"
: "${BIN_DIR:?}"
: "${TETRAGON_BIN:?}"

# RELAYD_DIR: the two relayd binaries (production and the testca,testtpm
# E3 build) MUST live outside /home and /root -- packaging/systemd/
# tetragon-relay.service's own ProtectHome=yes/InaccessiblePaths=/root
# /home (reproduced verbatim for every scenario below) would make a
# binary placed under $GITHUB_WORKSPACE (/home/runner/work/...)
# unreadable/un-exec'able to the sandboxed unit itself. /usr/libexec/
# tetragon-relay is the real production path (packaging/systemd/
# tetragon-relay.service's own ExecStart); BIN_DIR (the E3-only harness
# tools: e3controller/e3tetra/e3root/testenroll) is not exec'd under
# this sandbox at all, so it has no such constraint.
RELAYD_DIR=/usr/libexec/tetragon-relay

RELAY_YAML=/etc/tetragon-relay/relay.yaml
STORE_DIR=/var/lib/tetragon-relay
SPOOL_DIR=/var/spool/tetragon-relay
TRUST_DIR=/etc/tetragon-relay/trust
CA_CERT=${TRUST_DIR}/enrollment-ca.pem
ROOT_JSON=${TRUST_DIR}/root.json
TETRAGON_TP_DIR=/etc/tetragon/tetragon.tp.d/relay
TETRAGON_SOCKET=/var/run/tetragon/tetragon.sock

CONTROLLER_ADDR=127.0.0.1:18443
CONTROLLER_CERT=${TRUST_DIR}/controller-cert.pem
CONTROLLER_KEY=${TRUST_DIR}/controller-key.pem
CONTROLLER_SPIFFE=spiffe://e3.tetragon-relay.internal/mgmt/controller
TRUST_DOMAIN=e3.tetragon-relay.internal
HOST_UUID=11111111-1111-1111-1111-111111111111
BASELINE_POLICY_NAME=e3-baseline

SWTPM_CMD_PORT=12321
SWTPM_CTRL_PORT=12322
SWTPM_STATE_DIR=/var/lib/tetragon-relay-swtpm
SWTPM_CHARDEV_STATE_DIR=/var/lib/tetragon-relay-swtpm-chardev
PROD_TPM_DEVICE=/dev/tpmrm0
# The testtpm relayd build's --tpm-device for swtpm: both the command and
# the platform (control) channel, which go-tpm's tcp.Open always dials
# (cmd/relayd/tpmdevice_testtpm.go). 127.0.0.1, not localhost: the unit's
# IPAddressAllow is 127.0.0.1/32, so a localhost that resolves to ::1
# would be refused by the sandbox.
E3_TPM_DEVICE="tcp:127.0.0.1:${SWTPM_CMD_PORT},127.0.0.1:${SWTPM_CTRL_PORT}"

EXTRA_SYSTEMD_RUN_ARGS=()
RESULTS=()
record_result() {
	RESULTS+=("$1:$2")
	echo "E3 RESULT: $1 $2"
}

log() { echo "== $* =="; }

# ---------------------------------------------------------------------
# One-time setup: users/groups, directories, swtpm, relay.yaml, baseline
# policy.
# ---------------------------------------------------------------------

setup_users_and_dirs() {
	log "disabling swtpm's AppArmor profile"
	# Ubuntu's swtpm package ships an AppArmor profile that only
	# allow-lists /var/lib/libvirt/swtpm/** for NVRAM/lock file access
	# (github.com/stefanberger/swtpm/issues/852,
	# bugs.launchpad.net/ubuntu/+source/swtpm/+bug/2072524): any other
	# --tpmstate dir=... path -- including both of this script's own --
	# fails with "SWTPM_NVRAM_Lock_Dir: Could not open lockfile:
	# Permission denied" regardless of the directory's actual Unix
	# ownership/mode, which is what the first two E3 runs (45809746645,
	# 45813954637) both hit. Unloading the profile (rather than
	# relocating both state directories under /var/lib/libvirt/swtpm/,
	# a libvirt-owned path this project has no other reason to touch)
	# is a CI-environment accommodation, not a production security
	# change: relayd's own sandbox (reproduced verbatim below) is
	# completely unaffected.
	sudo apparmor_parser -R /etc/apparmor.d/usr.bin.swtpm 2>/dev/null || true

	log "users and groups"
	sudo groupadd -f tetragon-relay
	getent group tss >/dev/null || sudo groupadd tss
	if ! id tetragon-relay >/dev/null 2>&1; then
		sudo useradd --system --no-create-home --gid tetragon-relay --groups tss --shell /usr/sbin/nologin tetragon-relay
	fi

	log "directories"
	sudo mkdir -p "${TRUST_DIR}"
	sudo chown root:root /etc/tetragon-relay "${TRUST_DIR}"
	sudo chmod 0755 /etc/tetragon-relay "${TRUST_DIR}"

	sudo mkdir -p "${STORE_DIR}" "${SPOOL_DIR}"
	sudo chown tetragon-relay:tetragon-relay "${STORE_DIR}" "${SPOOL_DIR}"
	sudo chmod 0700 "${STORE_DIR}" "${SPOOL_DIR}"

	# SWTPM_STATE_DIR (the tcp: instance) is owned by THIS script's own
	# (unprivileged runner) user, not tetragon-relay: the tcp: transport
	# has no filesystem-permission concept at all (any process that can
	# reach the TCP port can use it), so swtpm itself never needs to run
	# as tetragon-relay, only relayd's own connection to it matters.
	# Running it as tetragon-relay previously failed outright
	# ("SWTPM_NVRAM_Lock_Dir: Could not open lockfile: Permission
	# denied") since that system user has no home directory and -- not
	# yet root-mapped into any session keyring -- cannot necessarily
	# acquire libtpms' own NVRAM lock the way an interactive user can.
	# /var/lib itself is root-owned, so creating a new directory under
	# it still needs sudo even though the directory's CONTENTS should
	# end up owned by this script's own user.
	sudo mkdir -p "${SWTPM_STATE_DIR}"
	sudo chown "$(id -u):$(id -g)" "${SWTPM_STATE_DIR}"

	# SWTPM_CHARDEV_STATE_DIR is used only by a root-run swtpm (sudo
	# swtpm chardev, below -- vtpm-proxy's /dev/vtpmx ioctl needs root
	# regardless), so it stays root-owned; no chown needed or wanted.
	sudo mkdir -p "${SWTPM_CHARDEV_STATE_DIR}"
}

# start_swtpm_chardev provides /dev/tpmrm0 for S1/S2 (the PRODUCTION
# relayd build, which only ever accepts exactly that path,
# cmd/relayd/tpmdevice.go). The kernel's tpm_vtpm_proxy driver
# (docs.kernel.org/security/tpm/tpm_vtpm_proxy.html) creates a real
# /dev/tpmN character device backed by a userspace emulator -- the
# kernel's own in-kernel TPM resource manager then creates the matching
# /dev/tpmrmN automatically, the same pairing a real TPM 2.0 device's
# /dev/tpmrm0 comes from, so this is not a shortcut around DeviceAllow=
# /dev/tpmrm0 rw: the production unit's actual device-access rule is
# exercised against a real character device, not reinterpreted. This is
# a SEPARATE, throwaway TPM instance from SWTPM_STATE_DIR's (the tcp:
# one S3-S6 use): S1/S2 never enroll an identity or touch anything the
# other scenarios' TPM state would need to agree with.
start_swtpm_chardev() {
	log "starting swtpm (chardev/vtpm-proxy, for /dev/tpmrm0)"
	sudo modprobe tpm_vtpm_proxy || true
	if [ ! -e /dev/vtpmx ]; then
		echo "tpm_vtpm_proxy did not create /dev/vtpmx; cannot provide /dev/tpmrm0 in this environment" >&2
		return 1
	fi
	# shellcheck disable=SC2024 # log file owned by this script's own
	# user, which is fine; nothing downstream needs it root-owned.
	sudo swtpm chardev --vtpm-proxy --tpm2 \
		--tpmstate "dir=${SWTPM_CHARDEV_STATE_DIR}" \
		--flags not-need-init >/tmp/swtpm-chardev.log 2>&1 &
	for _ in $(seq 1 50); do
		if [ -e "${PROD_TPM_DEVICE}" ]; then
			# Group "tss" (already SupplementaryGroups=tss in the real
			# unit, reproduced by systemd_run_properties) is this
			# project's own convention for TPM device access
			# (packaging/systemd/tetragon-relay.service); the kernel
			# creates the device root:root by default, so it must be
			# re-grouped for the sandboxed process to actually open it,
			# the same thing a real system's udev TPM rule would do.
			sudo chgrp tss "${PROD_TPM_DEVICE}"
			sudo chmod 0660 "${PROD_TPM_DEVICE}"
			return 0
		fi
		sleep 0.2
	done
	echo "${PROD_TPM_DEVICE} did not appear" >&2
	cat /tmp/swtpm-chardev.log >&2 || true
	return 1
}

start_swtpm_tcp() {
	log "starting swtpm (tcp, for cmd/testenroll and the testca,testtpm relayd build)"
	swtpm socket \
		--tpmstate "dir=${SWTPM_STATE_DIR}" \
		--ctrl "type=tcp,port=${SWTPM_CTRL_PORT}" \
		--server "type=tcp,port=${SWTPM_CMD_PORT}" \
		--tpm2 --flags not-need-init >/tmp/swtpm.log 2>&1 &
	for _ in $(seq 1 50); do
		if ss -ltn 2>/dev/null | grep -q ":${SWTPM_CMD_PORT} "; then
			return 0
		fi
		sleep 0.2
	done
	echo "swtpm did not start listening on port ${SWTPM_CMD_PORT}" >&2
	cat /tmp/swtpm.log >&2 || true
	return 1
}

write_relay_yaml() {
	log "writing ${RELAY_YAML}"
	sudo tee "${RELAY_YAML}" >/dev/null <<EOF
host:
  uuid: "${HOST_UUID}"
  allowed_scopes: ["e3-scope"]
controller:
  endpoints: ["${CONTROLLER_ADDR}"]
  spiffe_id: "${CONTROLLER_SPIFFE}"
  heartbeat_interval: "15s"
collector:
  endpoints: ["127.0.0.1:18444"]
  spiffe_id: "spiffe://${TRUST_DOMAIN}/mgmt/collector"
identity:
  trust_domain: "${TRUST_DOMAIN}"
  trust_bundle: "${CA_CERT}"
tetragon:
  socket: "${TETRAGON_SOCKET}"
  persist_dir: "${TETRAGON_TP_DIR}"
  allow_selinux_disabled: true
EOF
	sudo chown root:tetragon-relay "${RELAY_YAML}"
	sudo chmod 0640 "${RELAY_YAML}"
}

write_throwaway_ca() {
	# S1/S2 (C5: run before testenroll exists) still need SOME readable
	# PEM at identity.trust_bundle -- cmd/relayd's main() reads it
	# unconditionally before the UNENROLLED/no-production-Enroller
	# branch, even though no identity is ever built from it in those two
	# scenarios. A throwaway, unrelated self-signed cert satisfies the
	# "readable PEM file" requirement without needing cmd/testenroll's
	# TPM-backed identity flow at all.
	log "writing a throwaway CA cert for S1/S2 (overwritten by testenroll before S3)"
	tmpdir=$(mktemp -d)
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
		-keyout "${tmpdir}/key.pem" -out "${tmpdir}/cert.pem" \
		-days 1 -nodes -subj "/CN=e3 throwaway placeholder" >/dev/null 2>&1
	sudo cp "${tmpdir}/cert.pem" "${CA_CERT}"
	sudo chmod 0644 "${CA_CERT}"
	rm -rf "${tmpdir}"
}

write_root_json() {
	log "writing ${ROOT_JSON}"
	"${BIN_DIR}/e3root" --out /tmp/e3-root.json
	sudo cp /tmp/e3-root.json "${ROOT_JSON}"
	sudo chmod 0644 "${ROOT_JSON}"
}

preload_baseline_policy() {
	log "preloading the baseline ('pre-applied LKG') policy"
	"${BIN_DIR}/e3tetra" --mode=preload --tetragon-binary "${TETRAGON_BIN}" --policy-name "${BASELINE_POLICY_NAME}"
}

check_baseline_unchanged() {
	"${BIN_DIR}/e3tetra" --mode=check --tetragon-binary "${TETRAGON_BIN}" --expect-names "${BASELINE_POLICY_NAME}"
}

run_testenroll() {
	log "running cmd/testenroll"
	sudo -u tetragon-relay "${BIN_DIR}/testenroll" \
		--tpm-command-address "localhost:${SWTPM_CMD_PORT}" \
		--tpm-platform-address "localhost:${SWTPM_CTRL_PORT}" \
		--store-dir "${STORE_DIR}" \
		--trust-domain "${TRUST_DOMAIN}" \
		--host-uuid "${HOST_UUID}" \
		--ca-cert-out /tmp/e3-ca.pem \
		--controller-cert-out /tmp/e3-controller-cert.pem \
		--controller-key-out /tmp/e3-controller-key.pem \
		--controller-spiffe-id "${CONTROLLER_SPIFFE}"
	sudo cp /tmp/e3-ca.pem "${CA_CERT}"
	sudo cp /tmp/e3-controller-cert.pem "${CONTROLLER_CERT}"
	sudo cp /tmp/e3-controller-key.pem "${CONTROLLER_KEY}"
	sudo chmod 0644 "${CA_CERT}" "${CONTROLLER_CERT}"
	sudo chmod 0600 "${CONTROLLER_KEY}"
}

# ---------------------------------------------------------------------
# systemd-run wiring: reproduce every [Service] directive from the real
# unit file (packaging/systemd/tetragon-relay.service) as a
# `--property=` flag, verbatim, except IPAddressAllow (see below) and
# ExecStart/ExecStartPre (this function's own caller supplies the binary
# and arguments; ExecStartPre's host-facts/TPM-provisioning steps are
# replaced for E3 by cmd/testenroll, run separately, before relayd
# starts -- see docs/reports/step-06a.md section 9 for why).
# ---------------------------------------------------------------------

systemd_run_properties() {
	local unit_file="${REPO_ROOT}/packaging/systemd/tetragon-relay.service"
	while IFS= read -r raw; do
		line="${raw%%#*}"
		line="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
		[ -z "${line}" ] && continue
		case "${line}" in
		\[*\]) continue ;;
		esac
		key="${line%%=*}"
		val="${line#*=}"
		case "${key}" in
		ExecStart | ExecStartPre)
			continue
			;;
		IPAddressAllow)
			# Deviation (documented in docs/reports/step-06a.md): production's
			# 10.20.0.0/24 is the real management network, meaningless on a
			# GitHub-hosted runner. Substituted with the actual loopback
			# address the E3 test controller and swtpm listen on --
			# same shape (default-deny, allow exactly the controller's
			# address), same restrictiveness, different address because the
			# real one does not exist in CI.
			val="127.0.0.1/32"
			;;
		esac
		printf -- '--property=%s=%s\n' "${key}" "${val}"
	done < <(sed -n '/^\[Service\]/,/^\[Install\]/p' "${unit_file}")
}

# start_relayd_unit UNIT_NAME BINARY [ARGS...]
#
# EXTRA_SYSTEMD_RUN_ARGS (a global array, e.g. --setenv=FOO=bar), if set
# by the caller before invoking this function, is inserted before the
# parsed unit-file properties. Every property (including any multi-token
# value like SystemCallFilter's) is kept as exactly one array element
# throughout, so word-splitting can never silently break a directive
# into several bogus systemd-run arguments -- the bug this comment
# exists to prevent a future edit from reintroducing.
start_relayd_unit() {
	local unit_name="$1"
	shift
	local binary="$1"
	shift
	local -a props=()
	while IFS= read -r p; do props+=("${p}"); done < <(systemd_run_properties)
	sudo systemd-run --unit="${unit_name}" --collect \
		"${EXTRA_SYSTEMD_RUN_ARGS[@]}" \
		"${props[@]}" \
		"${binary}" "$@"
}

wait_for_unit_active() {
	local unit_name="$1"
	local timeout="${2:-20}"
	for _ in $(seq 1 "${timeout}"); do
		if sudo systemctl is-active --quiet "${unit_name}"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

stop_unit() {
	sudo systemctl stop "$1" 2>/dev/null || true
	sleep 1
}

# ---------------------------------------------------------------------
# S1: production build starts under the sandbox, stays UNENROLLED, sends
# READY=1, and Tetragon's pre-applied baseline is unchanged.
# ---------------------------------------------------------------------
scenario_s1() {
	log "S1: production build starts, stays UNENROLLED, baseline unchanged"
	if ! start_relayd_unit e3-relayd-s1 "${RELAYD_DIR}/relayd-prod" --config "${RELAY_YAML}"; then
		record_result S1 FAIL
		return
	fi
	if ! wait_for_unit_active e3-relayd-s1 20; then
		echo "e3-relayd-s1 did not become active (Type=notify needs READY=1)" >&2
		sudo journalctl -u e3-relayd-s1 --no-pager >&2 || true
		stop_unit e3-relayd-s1
		record_result S1 FAIL
		return
	fi
	sleep 3
	ok=true
	sudo systemctl is-active --quiet e3-relayd-s1 || ok=false
	check_baseline_unchanged || ok=false
	stop_unit e3-relayd-s1
	record_result S1 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S2: SIGTERM; relayd exits cleanly; Tetragon's loaded policies unchanged.
# ---------------------------------------------------------------------
scenario_s2() {
	log "S2: SIGTERM leaves Tetragon's loaded policies unchanged"
	if ! start_relayd_unit e3-relayd-s2 "${RELAYD_DIR}/relayd-prod" --config "${RELAY_YAML}"; then
		record_result S2 FAIL
		return
	fi
	if ! wait_for_unit_active e3-relayd-s2 20; then
		sudo journalctl -u e3-relayd-s2 --no-pager >&2 || true
		stop_unit e3-relayd-s2
		record_result S2 FAIL
		return
	fi
	sudo systemctl stop e3-relayd-s2
	sleep 1
	ok=true
	sudo systemctl is-active --quiet e3-relayd-s2 && ok=false # must have stopped
	check_baseline_unchanged || ok=false
	record_result S2 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S3: clean start to STEADY; the test controller observes Hello, then
# heartbeats roughly every 15s (at least 3).
# ---------------------------------------------------------------------
scenario_s3() {
	log "S3: clean start to STEADY with heartbeats"
	"${BIN_DIR}/e3controller" --listen "${CONTROLLER_ADDR}" --ca-cert "${CA_CERT}" \
		--cert "${CONTROLLER_CERT}" --key "${CONTROLLER_KEY}" --trust-domain "${TRUST_DOMAIN}" \
		--mode steady --min-heartbeats 3 --heartbeat-deadline 90s \
		>/tmp/e3controller-s3.log 2>&1 &
	ctrl_pid=$!
	sleep 1

	start_relayd_unit e3-relayd-s3 "${RELAYD_DIR}/relayd-e3" --config "${RELAY_YAML}" --tpm-device "${E3_TPM_DEVICE}"
	wait "${ctrl_pid}"
	ctrl_status=$?
	stop_unit e3-relayd-s3
	cat /tmp/e3controller-s3.log
	ok=true
	[ "${ctrl_status}" -eq 0 ] || ok=false
	check_baseline_unchanged || ok=false
	record_result S3 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S4: Terminate{REVOKED} stops reconnecting; Tetragon keeps enforcing.
# ---------------------------------------------------------------------
scenario_s4() {
	log "S4: Terminate{REVOKED} stops reconnecting"
	"${BIN_DIR}/e3controller" --listen "${CONTROLLER_ADDR}" --ca-cert "${CA_CERT}" \
		--cert "${CONTROLLER_CERT}" --key "${CONTROLLER_KEY}" --trust-domain "${TRUST_DOMAIN}" \
		--mode revoke --reconnect-assert-for 65s \
		>/tmp/e3controller-s4.log 2>&1 &
	ctrl_pid=$!
	sleep 1

	start_relayd_unit e3-relayd-s4 "${RELAYD_DIR}/relayd-e3" --config "${RELAY_YAML}" --tpm-device "${E3_TPM_DEVICE}"
	wait "${ctrl_pid}"
	ctrl_status=$?
	stop_unit e3-relayd-s4
	cat /tmp/e3controller-s4.log
	ok=true
	[ "${ctrl_status}" -eq 0 ] || ok=false
	check_baseline_unchanged || ok=false
	record_result S4 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S5: controller unavailable -> DEGRADED after the threshold (shortened
# via a testca-tagged constant override, RELAYD_E3_DEGRADED_TIMEOUT --
# step-06a-e3-prompt.md explicitly permits this). No controller process
# is started at all for this scenario. This proves the weaker property
# docs/reports/step-06a.md section 9's open question 6 offered as a
# fallback (no connection ever completes; Tetragon keeps enforcing
# throughout) rather than relayd's literal internal state, since this
# repository has no state-observability surface today (see the report
# for the full reasoning).
# ---------------------------------------------------------------------
scenario_s5() {
	log "S5: controller unavailable; Tetragon keeps enforcing"
	EXTRA_SYSTEMD_RUN_ARGS=(--setenv=RELAYD_E3_DEGRADED_TIMEOUT=10s)
	start_relayd_unit e3-relayd-s5 "${RELAYD_DIR}/relayd-e3" --config "${RELAY_YAML}" --tpm-device "${E3_TPM_DEVICE}"
	EXTRA_SYSTEMD_RUN_ARGS=()
	sleep 20
	ok=true
	sudo systemctl is-active --quiet e3-relayd-s5 || ok=false # relayd itself must not have crashed
	check_baseline_unchanged || ok=false
	stop_unit e3-relayd-s5
	record_result S5 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S6: a stalled session runner (RELAYD_E3_STALL_COMPONENT) withholds
# WATCHDOG=1; the audit record (internal/audit.JSONAuditor -> stderr ->
# journal, ADR 0033) names the stale component; systemd restarts relayd.
# ---------------------------------------------------------------------
scenario_s6() {
	log "S6: stalled session runner withholds the watchdog; systemd restarts relayd"
	"${BIN_DIR}/e3controller" --listen "${CONTROLLER_ADDR}" --ca-cert "${CA_CERT}" \
		--cert "${CONTROLLER_CERT}" --key "${CONTROLLER_KEY}" --trust-domain "${TRUST_DOMAIN}" \
		--mode steady --min-heartbeats 1 --heartbeat-deadline 30s \
		>/tmp/e3controller-s6.log 2>&1 &
	ctrl_pid=$!

	EXTRA_SYSTEMD_RUN_ARGS=(--setenv=RELAYD_E3_STALL_COMPONENT=session_runner)
	start_relayd_unit e3-relayd-s6 "${RELAYD_DIR}/relayd-e3" --config "${RELAY_YAML}" --tpm-device "${E3_TPM_DEVICE}"
	EXTRA_SYSTEMD_RUN_ARGS=()

	wait "${ctrl_pid}" || true # just needs to observe the first heartbeat; its own exit code is not S6's pass/fail signal
	cat /tmp/e3controller-s6.log

	restarts_before=$(systemctl show e3-relayd-s6 -p NRestarts --value 2>/dev/null || echo 0)
	# sessionLivenessMaxInterval (20s) until session_runner is first
	# considered stale, plus up to two withheld 15s watchdog checks
	# before WatchdogSec (30s) elapses without a ping: generous margin.
	sleep 90
	restarts_after=$(systemctl show e3-relayd-s6 -p NRestarts --value 2>/dev/null || echo 0)

	ok=true
	[ "${restarts_after}" -gt "${restarts_before}" ] || ok=false
	sudo journalctl -u e3-relayd-s6 --no-pager | grep -q "watchdog_withheld" || ok=false
	sudo journalctl -u e3-relayd-s6 --no-pager | grep -q "session_runner" || ok=false
	stop_unit e3-relayd-s6
	record_result S6 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

main() {
	setup_users_and_dirs
	tcp_tpm_ok=true
	start_swtpm_tcp || tcp_tpm_ok=false
	write_relay_yaml
	write_throwaway_ca
	write_root_json
	preload_baseline_policy

	# C5: the two identity-free scenarios first, then testenroll, then
	# the identity scenarios. S1/S2 additionally need their own
	# /dev/tpmrm0 (the production build's crypto self-test/store/host-
	# signer sequence runs unconditionally, before the UNENROLLED branch
	# C2 describes -- it is not actually identity-free at the TPM level,
	# only enrollment-free).
	if ! start_swtpm_chardev; then
		record_result S1 FAIL
		record_result S2 FAIL
	else
		scenario_s1
		scenario_s2
	fi

	if [ "${tcp_tpm_ok}" = true ]; then
		run_testenroll
		scenario_s3
		scenario_s4
		scenario_s5
		scenario_s6
	else
		echo "the tcp: swtpm instance never started listening; skipping every scenario that needs it" >&2
		record_result S3 FAIL
		record_result S4 FAIL
		record_result S5 FAIL
		record_result S6 FAIL
	fi

	echo
	echo "== E3 summary =="
	fail=0
	for r in "${RESULTS[@]}"; do
		echo "${r}"
		case "${r}" in
		*:FAIL) fail=1 ;;
		esac
	done
	exit "${fail}"
}

main "$@"

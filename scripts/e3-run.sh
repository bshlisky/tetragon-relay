#!/usr/bin/env bash
# docs/prompts/step-06a-e3-prompt.md: runs relayd as the REAL systemd
# unit (packaging/systemd/tetragon-relay.service, installed unmodified
# into /etc/systemd/system/), against a real Tetragon and the E3 test
# controller (cmd/e3controller), for every one of S1-S6. Every directive,
# including both ExecStartPre=+relay-probe lines, Type=notify,
# WatchdogSec, Restart and RestartSec, comes from that file. The only
# differences are drop-ins under /etc/systemd/system/
# tetragon-relay.service.d/ (write_dropins below; every line and its
# reason is listed in docs/reports/step-06a.md). S1/S2 run with none.
#
# Run by .github/workflows/ci.yml's "e3" job on ubuntu-24.04, after that
# job has: installed swtpm, installed Tetragon at /usr/local/bin/tetragon
# (the path the unit's host-facts ExecStartPre hashes) and started it as
# the transient unit tetragon.service (the unit's BindsTo=), and built
# every binary this script invokes: relayd (no tags) at the unit's own
# ExecStart path, relayd-e3 (-tags testca), relay-probe (no
# tags), plus cmd/testenroll, cmd/e3root, cmd/e3controller, cmd/e3tetra
# with their own tags. REPO_ROOT, BIN_DIR and TETRAGON_BIN must be set.
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

# RELAYD_DIR: the two relayd binaries (production and the testca
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
# The E3 test controller's own certificate and private key. They belong
# to cmd/e3controller, which runs as this script's (runner) user, not to
# relayd, so they live in a runner-owned directory outside
# /etc/tetragon-relay: E3 run 45817131291 (S3, S4, S6) failed with
# "open .../trust/controller-key.pem: permission denied" when the key was
# root-owned 0600 under relayd's trust directory. relayd never needs the
# controller's private key; under the unit's PrivateTmp=yes it cannot
# even see this directory.
CONTROLLER_DIR=/tmp/e3-controller
CONTROLLER_CERT=${CONTROLLER_DIR}/controller-cert.pem
CONTROLLER_KEY=${CONTROLLER_DIR}/controller-key.pem
CONTROLLER_SPIFFE=spiffe://e3.tetragon-relay.internal/mgmt/controller
TRUST_DOMAIN=e3.tetragon-relay.internal
HOST_UUID=11111111-1111-1111-1111-111111111111
BASELINE_POLICY_NAME=e3-baseline

SWTPM_CHARDEV_STATE_DIR=/var/lib/tetragon-relay-swtpm-chardev
PROD_TPM_DEVICE=/dev/tpmrm0

UNIT=tetragon-relay
UNIT_FILE=/etc/systemd/system/${UNIT}.service
DROPIN_DIR=/etc/systemd/system/${UNIT}.service.d

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


	# SWTPM_CHARDEV_STATE_DIR is used only by a root-run swtpm (sudo
	# swtpm chardev, below -- vtpm-proxy's /dev/vtpmx ioctl needs root
	# regardless), so it stays root-owned.
	sudo mkdir -p "${SWTPM_CHARDEV_STATE_DIR}"
}

# start_swtpm_chardev provides /dev/tpmrm0, the one TPM every scenario
# uses. The kernel's tpm_vtpm_proxy driver
# (docs.kernel.org/security/tpm/tpm_vtpm_proxy.html) creates a real
# /dev/tpmN character device backed by a userspace emulator -- the
# kernel's own in-kernel TPM resource manager then creates the matching
# /dev/tpmrmN automatically, the same pairing a real TPM 2.0 device's
# /dev/tpmrm0 comes from, so this is not a shortcut around DeviceAllow=
# /dev/tpmrm0 rw: the production unit's actual device-access rule is
# exercised against a real character device. All six scenarios share
# this TPM: the store and host-signer blobs S1/S2 create are bound to it,
# and E3 run 45854346976 showed a second (TCP) swtpm rejecting them with
# TPM_RC_INTEGRITY. It is not provisioned here: the real unit's
# ExecStartPre=+relay-probe --provision-tpm does that on every start.
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
			# Group "tss" (SupplementaryGroups=tss in the real unit) is
			# this project's convention for TPM device access; the
			# kernel creates the device root:root, so it is re-grouped
			# here, the same thing a real system's udev TPM rule does.
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
		--tpm-device "${PROD_TPM_DEVICE}" \
		--store-dir "${STORE_DIR}" \
		--trust-domain "${TRUST_DOMAIN}" \
		--host-uuid "${HOST_UUID}" \
		--ca-cert-out /tmp/e3-ca.pem \
		--controller-cert-out /tmp/e3-controller-cert.pem \
		--controller-key-out /tmp/e3-controller-key.pem \
		--controller-spiffe-id "${CONTROLLER_SPIFFE}" &&
		sudo cp /tmp/e3-ca.pem "${CA_CERT}" &&
		sudo chmod 0644 "${CA_CERT}" &&
		mkdir -p "${CONTROLLER_DIR}" &&
		chmod 0700 "${CONTROLLER_DIR}" &&
		sudo install -o "$(id -u)" -g "$(id -g)" -m 0644 /tmp/e3-controller-cert.pem "${CONTROLLER_CERT}" &&
		sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 /tmp/e3-controller-key.pem "${CONTROLLER_KEY}" &&
		sudo rm -f /tmp/e3-controller-key.pem
}

# ---------------------------------------------------------------------
# The real unit, plus drop-ins. install_unit copies packaging/systemd/
# tetragon-relay.service byte for byte; nothing in this script edits it.
# write_dropins replaces the whole drop-in directory with exactly the
# files a scenario needs (none for S1/S2), so no scenario inherits
# another's override. Every drop-in line is listed, with its reason, in
# docs/reports/step-06a.md.
# ---------------------------------------------------------------------

install_unit() {
	log "installing the real unit file, unmodified"
	sudo install -o root -g root -m 0644 "${REPO_ROOT}/packaging/systemd/tetragon-relay.service" "${UNIT_FILE}"
	cmp "${REPO_ROOT}/packaging/systemd/tetragon-relay.service" "${UNIT_FILE}"
	sudo mkdir -p "${DROPIN_DIR}"
}

# e3_dropin: S3-S6 only. Two directives, each the minimum a test-only
# difference needs:
#  - ExecStart: the testca build (C4) instead of the production
#    binary, same arguments. "ExecStart=" first clears the unit's own
#    value (systemd.service(5): a drop-in must reset ExecStart before
#    setting it for a Type= other than oneshot). ExecStartPre is NOT
#    touched: both root relay-probe lines run as in production.
#  - IPAddressAllow: the unit allows only 10.20.0.0/24 (the real
#    management network, absent on a GitHub runner); the E3 controller
#    listens on 127.0.0.1. "IPAddressAllow=" resets the list
#    (systemd.resource-control(5)), then exactly one /32 is allowed.
#    IPAddressDeny=any stays from the unit.
e3_dropin() {
	cat <<EOF
[Service]
ExecStart=
ExecStart=${RELAYD_DIR}/relayd-e3 --config ${RELAY_YAML}
IPAddressAllow=
IPAddressAllow=127.0.0.1/32
EOF
}

# write_dropins NAME=CONTENT...: replace the drop-in directory's contents
# with exactly these files, then daemon-reload.
write_dropins() {
	sudo find "${DROPIN_DIR}" -maxdepth 1 -type f -name '*.conf' -delete
	local arg name
	for arg in "$@"; do
		name="${arg%%=*}"
		printf '%s\n' "${arg#*=}" | sudo tee "${DROPIN_DIR}/${name}" >/dev/null
		sudo chmod 0644 "${DROPIN_DIR}/${name}"
	done
	sudo systemctl daemon-reload
	# Evidence: the effective unit, and the directives S6 depends on.
	sudo systemctl cat "${UNIT}" --no-pager | grep -vE '^\s*#|^\s*$' || true
	systemctl show "${UNIT}" -p Type -p WatchdogUSec -p Restart -p RestartUSec -p IPAddressAllow -p Environment --no-pager
}

# start_unit: Type=notify, so `systemctl start` returns only after
# READY=1 (or fails if the ExecStartPre lines or relayd fail first).
start_unit() {
	SCENARIO_SINCE=$(date '+%Y-%m-%d %H:%M:%S')
	sudo systemctl reset-failed "${UNIT}" 2>/dev/null || true
	sudo systemctl start "${UNIT}"
}

stop_unit() {
	sudo systemctl stop "${UNIT}" 2>/dev/null || true
	sleep 1
}

scenario_journal() {
	sudo journalctl -u "${UNIT}" --since "${SCENARIO_SINCE}" --no-pager
}

# no_sandbox_read_failures: ADR 0034 / step-06a-e3-decisions.md D3
# evidence. Under the real unit (ProcSubset=pid, ProtectProc=invisible,
# ProtectSystem=strict) relayd must have accepted the host facts
# (no "host_facts" fail-closed record: the file is root-owned 0640 on the
# /run tmpfs) and read /proc/self/exe (no "agent_build_digest" record).
no_sandbox_read_failures() {
	local j
	j=$(scenario_journal)
	if grep -E '"step":"(host_facts|host_facts_boot_id|agent_build_digest)"' <<<"${j}"; then
		echo "relayd reported a host-facts or /proc read failure under the unit" >&2
		return 1
	fi
}

# host_facts_written: the second ExecStartPre=+ line wrote host facts
# for this start (RuntimeDirectory= is removed on stop, so a file here
# is from the current start).
host_facts_written() {
	sudo test -s /run/tetragon-relay/host-facts.json
}

# ---------------------------------------------------------------------
# S1: production build starts under the real unit, stays UNENROLLED,
# sends READY=1, and Tetragon's pre-applied baseline is unchanged.
# ---------------------------------------------------------------------
scenario_s1() {
	log "S1: production build starts, stays UNENROLLED, baseline unchanged"
	write_dropins
	ok=true
	if ! start_unit; then
		echo "${UNIT} did not start (ExecStartPre failure, or no READY=1)" >&2
		ok=false
	else
		sleep 3
		sudo systemctl is-active --quiet "${UNIT}" || ok=false
		host_facts_written || { echo "host facts missing" >&2; ok=false; }
		no_sandbox_read_failures || ok=false
	fi
	check_baseline_unchanged || ok=false
	scenario_journal
	stop_unit
	record_result S1 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S2: SIGTERM; relayd exits cleanly; Tetragon's loaded policies unchanged.
# ---------------------------------------------------------------------
scenario_s2() {
	log "S2: SIGTERM leaves Tetragon's loaded policies unchanged"
	write_dropins
	ok=true
	if ! start_unit; then
		ok=false
	else
		sudo systemctl stop "${UNIT}" # KillSignal defaults to SIGTERM
		sleep 1
		sudo systemctl is-active --quiet "${UNIT}" && ok=false
		# Clean exit: systemd records Result=success after SIGTERM.
		[ "$(systemctl show "${UNIT}" -p Result --value)" = success ] || ok=false
	fi
	check_baseline_unchanged || ok=false
	scenario_journal
	record_result S2 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

start_controller() {
	local name="$1"
	shift
	"${BIN_DIR}/e3controller" --listen "${CONTROLLER_ADDR}" --ca-cert "${CA_CERT}" \
		--cert "${CONTROLLER_CERT}" --key "${CONTROLLER_KEY}" --trust-domain "${TRUST_DOMAIN}" \
		"$@" >"/tmp/e3controller-${name}.log" 2>&1 &
	ctrl_pid=$!
	sleep 1
}

# ---------------------------------------------------------------------
# S3: clean start to STEADY; the test controller observes Hello, then
# heartbeats roughly every 15s (at least 3).
# ---------------------------------------------------------------------
scenario_s3() {
	log "S3: clean start to STEADY with heartbeats"
	write_dropins "e3.conf=$(e3_dropin)"
	start_controller s3 --mode steady --min-heartbeats 3 --heartbeat-deadline 90s
	ok=true
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s3.log
	no_sandbox_read_failures || ok=false
	check_baseline_unchanged || ok=false
	scenario_journal
	stop_unit
	record_result S3 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S4: Terminate{REVOKED} stops reconnecting; Tetragon keeps enforcing.
# Runs LAST: the REVOKED marker is persisted in the store (ADR 0035) and
# only operator re-enrollment clears it, so any scenario after S4 would
# start parked. Mid-scenario relayd is restarted to prove the marker
# survives a restart (D2), and the parked runner must keep the watchdog
# fed (D1): no "Watchdog timeout" in S4's journal.
# ---------------------------------------------------------------------
wait_journal_step() {
	local step="$1" timeout="$2"
	for _ in $(seq 1 "${timeout}"); do
		if scenario_journal | grep -q "\"step\":\"${step}\""; then
			return 0
		fi
		sleep 1
	done
	echo "no ${step} record within ${timeout}s" >&2
	return 1
}

scenario_s4() {
	log "S4: Terminate{REVOKED} stops reconnecting, across a restart"
	write_dropins "e3.conf=$(e3_dropin)"
	start_controller s4 --mode revoke --reconnect-assert-for 65s
	ok=true
	start_unit || ok=false
	wait_journal_step revocation_persisted 20 || ok=false
	sudo systemctl restart "${UNIT}" || ok=false
	wait_journal_step revocation_restored 20 || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s4.log
	journal=$(scenario_journal)
	echo "${journal}"
	sudo systemctl is-active --quiet "${UNIT}" || { echo "relayd not running (parked) at the end of S4" >&2; ok=false; }
	if grep -q 'Watchdog timeout' <<<"${journal}"; then
		echo "systemd watchdog fired while REVOKED (D1)" >&2
		ok=false
	fi
	check_baseline_unchanged || ok=false
	stop_unit
	record_result S4 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S5: controller unavailable -> DEGRADED after the threshold, shortened
# through the testca-tagged override RELAYD_E3_DEGRADED_TIMEOUT (the E3
# prompt permits exactly this, under C4). No controller is started.
# ---------------------------------------------------------------------
scenario_s5() {
	log "S5: controller unavailable; Tetragon keeps enforcing"
	write_dropins "e3.conf=$(e3_dropin)" \
		"e3-s5.conf=$(printf '[Service]\nEnvironment=RELAYD_E3_DEGRADED_TIMEOUT=10s')"
	ok=true
	start_unit || ok=false
	sleep 20
	sudo systemctl is-active --quiet "${UNIT}" || ok=false # relayd itself must not have crashed
	check_baseline_unchanged || ok=false
	scenario_journal
	stop_unit
	record_result S5 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S6: a stalled session runner (testca hook RELAYD_E3_STALL_COMPONENT)
# withholds WATCHDOG=1; the audit record (internal/audit.JSONAuditor ->
# stderr -> journal, ADR 0033) names the stale component; systemd's own
# watchdog (WatchdogSec=30s from the real unit) kills relayd and its own
# Restart=always/RestartSec=2s restarts it. Both are checked in the
# journal ("Watchdog timeout"), not inferred.
# ---------------------------------------------------------------------
scenario_s6() {
	log "S6: stalled session runner withholds the watchdog; systemd restarts relayd"
	write_dropins "e3.conf=$(e3_dropin)" \
		"e3-s6.conf=$(printf '[Service]\nEnvironment=RELAYD_E3_STALL_COMPONENT=session_runner')"
	start_controller s6 --mode steady --min-heartbeats 1 --heartbeat-deadline 30s
	ok=true
	start_unit || ok=false
	wait "${ctrl_pid}" || true # only needs to observe the first heartbeat
	cat /tmp/e3controller-s6.log

	restarts_before=$(systemctl show "${UNIT}" -p NRestarts --value)
	# sessionLivenessMaxInterval (20s) until session_runner is stale, then
	# WatchdogSec (30s) without a ping, then RestartSec (2s): margin.
	sleep 90
	restarts_after=$(systemctl show "${UNIT}" -p NRestarts --value)
	echo "NRestarts: before=${restarts_before} after=${restarts_after}"

	journal=$(scenario_journal)
	echo "${journal}"
	[ "${restarts_after}" -gt "${restarts_before}" ] || ok=false
	grep -q 'Watchdog timeout' <<<"${journal}" || { echo "no systemd watchdog timeout in the journal" >&2; ok=false; }
	grep -q '"step":"watchdog_withheld"' <<<"${journal}" || ok=false
	grep '"step":"watchdog_withheld"' <<<"${journal}" | grep -q 'session_runner' || ok=false
	check_baseline_unchanged || ok=false
	stop_unit
	record_result S6 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

main() {
	setup_users_and_dirs
	write_relay_yaml
	write_throwaway_ca
	write_root_json
	preload_baseline_policy
	install_unit

	if ! start_swtpm_chardev; then
		echo "no /dev/tpmrm0; every scenario needs it" >&2
		for s in S1 S2 S3 S4 S5 S6; do record_result "${s}" FAIL; done
	else
		# C5: the two identity-free scenarios first, then testenroll,
		# then the identity scenarios.
		scenario_s1
		scenario_s2
		if run_testenroll; then
			scenario_s3
			scenario_s5
			scenario_s6
			scenario_s4 # last: revocation is terminal for this store (ADR 0035)
		else
			for s in S3 S4 S5 S6; do record_result "${s}" FAIL; done
		fi
		write_dropins
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

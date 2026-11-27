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
# Step 7a: cmd/e3collector, the test collector (runner-owned, like the
# controller). Its endpoint is inside the e3 drop-in's IPAddressAllow
# (127.0.0.1/32) and matches relay.yaml's collector.endpoints.
COLLECTOR_ADDR=127.0.0.1:18444
COLLECTOR_DIR=/tmp/e3-collector
COLLECTOR_CERT=${COLLECTOR_DIR}/collector-cert.pem
COLLECTOR_KEY=${COLLECTOR_DIR}/collector-key.pem
COLLECTOR_SPIFFE=spiffe://e3.tetragon-relay.internal/mgmt/collector
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

	# Step 6b (S7, S12): enforce bundles need host facts with
	# usrmerge_ok (internal/agent BundleDeps.EnforceAllowed). relay-probe
	# requires RHEL 9's /var/run -> ../run; Ubuntu 24.04 ships
	# /var/run -> /run (integration job run 45929721297: "usrmerge_detail":
	# "/var/run: symlink target is \"/run\", want \"../run\""). Both name
	# the same directory. The runner is made to match the production
	# platform rather than the check being relaxed; this is CI-environment
	# scaffolding like the AppArmor change above, and relayd's sandbox is
	# untouched.
	log "making /var/run the RHEL-style relative symlink to ../run"
	sudo ln -sfn ../run /var/run
	readlink /var/run

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
  spiffe_id: "${COLLECTOR_SPIFFE}"
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

# E3_KEYS: the E3 test root's private keys (step 6b F2), kept by e3root
# in a runner-owned directory relayd never reads (it runs under
# PrivateTmp=yes and cannot see /tmp at all). v1/targets.key signs the
# S7-S9 bundles.
E3_KEYS=/tmp/e3-keys
BUNDLE_DIR=/tmp/e3-bundles
SCOPE=e3-scope
CANARY=/usr/local/bin/e3-canary-sh

write_root_json() {
	log "writing ${ROOT_JSON}"
	mkdir -p "${E3_KEYS}" "${BUNDLE_DIR}"
	chmod 0700 "${E3_KEYS}"
	"${BIN_DIR}/e3root" --out /tmp/e3-root.json --keys-out "${E3_KEYS}/v1"
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
		--controller-spiffe-id "${CONTROLLER_SPIFFE}" \
		--collector-cert-out /tmp/e3-collector-cert.pem \
		--collector-key-out /tmp/e3-collector-key.pem \
		--collector-spiffe-id "${COLLECTOR_SPIFFE}" &&
		sudo cp /tmp/e3-ca.pem "${CA_CERT}" &&
		sudo chmod 0644 "${CA_CERT}" &&
		mkdir -p "${CONTROLLER_DIR}" &&
		chmod 0700 "${CONTROLLER_DIR}" &&
		sudo install -o "$(id -u)" -g "$(id -g)" -m 0644 /tmp/e3-controller-cert.pem "${CONTROLLER_CERT}" &&
		sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 /tmp/e3-controller-key.pem "${CONTROLLER_KEY}" &&
		sudo rm -f /tmp/e3-controller-key.pem &&
		mkdir -p "${COLLECTOR_DIR}" &&
		chmod 0700 "${COLLECTOR_DIR}" &&
		sudo install -o "$(id -u)" -g "$(id -g)" -m 0644 /tmp/e3-collector-cert.pem "${COLLECTOR_CERT}" &&
		sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 /tmp/e3-collector-key.pem "${COLLECTOR_KEY}" &&
		sudo rm -f /tmp/e3-collector-key.pem
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
	# S7 left relay-managed policies loaded, so S4 compares against what
	# is loaded when it starts rather than against the baseline alone.
	loaded_before=$(loaded_names)
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
	check_loaded_unchanged "${loaded_before}" || ok=false
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

# ---------------------------------------------------------------------
# Step 6b: bundles delivered over the stream (S7-S9). Bundles are signed
# here, at scenario time, by cmd/bundlesign-test e3-bundle (testtools
# tag) with the E3 test root's targets key.
# ---------------------------------------------------------------------

loaded_names() {
	"${BIN_DIR}/e3tetra" --mode=list --tetragon-binary "${TETRAGON_BIN}" | tr '\n' ',' | sed 's/,$//'
}

check_loaded_unchanged() {
	local before="$1" after
	after=$(loaded_names)
	echo "loaded before: ${before}"
	echo "loaded after:  ${after}"
	[ "${before}" = "${after}" ]
}

# sign_bundle OUT KEY EPOCH MODE NAME=YAMLFILE...
sign_bundle() {
	local out="$1" key="$2" epoch="$3" mode="$4"
	shift 4
	local args=() p
	for p in "$@"; do args+=(--policy "${p}"); done
	"${BIN_DIR}/bundlesign-test" e3-bundle --key "${key}" --out "${out}" \
		--scope "${SCOPE}" --epoch "${epoch}" --mode "${mode}" --host-uuid "${HOST_UUID}" "${args[@]}"
}

# canary_policy NAME BINARY: Sigkill on security_bprm_check for BINARY as
# the exec caller (ADR 0020: the hook reports the caller, so the canary
# is killed when it execs its next command).
canary_policy() {
	cat <<POLICY
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "$1"
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "$2"
        matchActions:
        - action: "Sigkill"
POLICY
}

# run_canary: a private copy of bash (never the real /usr/bin/bash) that
# execs two external commands, so it is the caller of an exec (ADR 0020;
# two commands, because bash tail-calls a single trailing one). Prints
# the exit status: 137 (128+SIGKILL) means the canary was killed.
run_canary() {
	local rc=0
	timeout 20 "${CANARY}" -c "/usr/bin/true; /usr/bin/true" || rc=$?
	echo "${rc}"
}

prepare_s7_bundles() {
	sudo install -o root -g root -m 0755 /usr/bin/bash "${CANARY}"
	canary_policy e3-canary "${CANARY}" >"${BUNDLE_DIR}/e3-canary.yaml"
	sign_bundle "${BUNDLE_DIR}/s7-monitor.json" "${E3_KEYS}/v1/targets.key" 1 monitor "e3-canary=${BUNDLE_DIR}/e3-canary.yaml" &&
		sign_bundle "${BUNDLE_DIR}/s7-enforce.json" "${E3_KEYS}/v1/targets.key" 2 enforce "e3-canary=${BUNDLE_DIR}/e3-canary.yaml"
}

# ---------------------------------------------------------------------
# S7: a monitor bundle, then an enforce bundle, over the stream. Both
# APPLIED (each after its 60 s health window, with heartbeats throughout);
# the canary is killed under the enforce bundle; after a restart the
# persisted epoch (2) is reported in a StateReport.
# ---------------------------------------------------------------------
scenario_s7() {
	log "S7: monitor then enforce bundle over the stream; canary killed; epoch persists"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	prepare_s7_bundles || ok=false
	echo "canary before any bundle: rc=$(run_canary)"
	start_controller s7 --mode bundles --overall-timeout 420s --apply-timeout 180s \
		--min-heartbeats-during-apply 3 \
		--bundle "${BUNDLE_DIR}/s7-monitor.json" --expect APPLIED \
		--bundle "${BUNDLE_DIR}/s7-enforce.json" --expect APPLIED
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s7.log
	echo "loaded after S7's bundles: $(loaded_names)"
	rc=$(run_canary)
	echo "canary under the enforce bundle: rc=${rc}"
	[ "${rc}" = 137 ] || { echo "canary was not killed (rc=${rc}, want 137)" >&2; ok=false; }
	scenario_journal
	stop_unit

	log "S7: restart; the persisted epoch survives"
	start_controller s7-restart --mode state --expect-epoch "${SCOPE}=2"
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s7-restart.log
	scenario_journal
	stop_unit
	record_result S7 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S8: a bundle signed by a key outside the trust root gets
# REJECTED_SIGNATURE, and nothing changes in Tetragon.
# ---------------------------------------------------------------------
scenario_s8() {
	log "S8: bad signature -> REJECTED_SIGNATURE, Tetragon unchanged"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	"${BIN_DIR}/e3root" --out /tmp/e3-bogus-root.json --keys-out "${E3_KEYS}/bogus" || ok=false
	canary_policy e3-bogus /tmp/e3-never-run >"${BUNDLE_DIR}/e3-bogus.yaml"
	sign_bundle "${BUNDLE_DIR}/s8-badsig.json" "${E3_KEYS}/bogus/targets.key" 3 monitor "e3-bogus=${BUNDLE_DIR}/e3-bogus.yaml" || ok=false
	before=$(loaded_names)
	start_controller s8 --mode bundles --overall-timeout 120s --apply-timeout 60s \
		--bundle "${BUNDLE_DIR}/s8-badsig.json" --expect REJECTED_SIGNATURE
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s8.log
	check_loaded_unchanged "${before}" || ok=false
	scenario_journal
	stop_unit
	record_result S8 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S9: replaying S7's enforce bundle (epoch 2, already persisted) gets
# REJECTED_EPOCH, and nothing changes in Tetragon.
# ---------------------------------------------------------------------
scenario_s9() {
	log "S9: replay of S7's bundle -> REJECTED_EPOCH, Tetragon unchanged"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	before=$(loaded_names)
	start_controller s9 --mode bundles --overall-timeout 120s --apply-timeout 60s \
		--bundle "${BUNDLE_DIR}/s7-enforce.json" --expect REJECTED_EPOCH
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s9.log
	check_loaded_unchanged "${before}" || ok=false
	scenario_journal
	stop_unit
	record_result S9 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}
# ---------------------------------------------------------------------
# S10: a TrustUpdate carrying root versions 2 and 3 (each signed by its
# predecessor's root key and its own) is adopted and persisted; a bundle
# signed under root 3's targets key is APPLIED. After a restart (the
# RPM-shipped root.json is still version 1) a second bundle under root 3
# is APPLIED too, which proves version 3 was persisted and restored.
# ---------------------------------------------------------------------
scenario_s10() {
	log "S10: trust update chain v2, v3 over the stream; persisted across a restart"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	"${BIN_DIR}/e3root" --version 2 --prev-keys "${E3_KEYS}/v1" --keys-out "${E3_KEYS}/v2" --out "${BUNDLE_DIR}/root-v2.json" || ok=false
	"${BIN_DIR}/e3root" --version 3 --prev-keys "${E3_KEYS}/v2" --keys-out "${E3_KEYS}/v3" --out "${BUNDLE_DIR}/root-v3.json" || ok=false
	canary_policy e3-s10 /tmp/e3-never-run >"${BUNDLE_DIR}/e3-s10.yaml"
	sign_bundle "${BUNDLE_DIR}/s10-a.json" "${E3_KEYS}/v3/targets.key" 3 monitor "e3-s10=${BUNDLE_DIR}/e3-s10.yaml" || ok=false
	sign_bundle "${BUNDLE_DIR}/s10-b.json" "${E3_KEYS}/v3/targets.key" 4 monitor "e3-s10=${BUNDLE_DIR}/e3-s10.yaml" || ok=false
	start_controller s10 --mode bundles --overall-timeout 300s --apply-timeout 180s \
		--trust-update "${BUNDLE_DIR}/root-v2.json" --trust-update "${BUNDLE_DIR}/root-v3.json" \
		--bundle "${BUNDLE_DIR}/s10-a.json" --expect APPLIED
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s10.log
	journal=$(scenario_journal)
	echo "${journal}"
	grep '"step":"trust_root_adopted"' <<<"${journal}" | grep -q 'version 3' || { echo "no trust_root_adopted for version 3" >&2; ok=false; }
	stop_unit

	log "S10: restart; root version 3 is restored from the store"
	start_controller s10-restart --mode bundles --overall-timeout 300s --apply-timeout 180s \
		--bundle "${BUNDLE_DIR}/s10-b.json" --expect APPLIED
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s10-restart.log
	scenario_journal
	stop_unit
	record_result S10 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}
# ---------------------------------------------------------------------
# S11: an out-of-band delete of a relay-managed policy (S10's e3-s10,
# domain "relay-managed") through Tetragon's own socket. The next
# reconcile cycle (at most 60 s) finds the drift: Alert DRIFT, LKG
# re-asserted once, and the policy is loaded again.
# ---------------------------------------------------------------------
scenario_s11() {
	log "S11: out-of-band delete of a relay-managed policy -> Alert DRIFT, re-assert"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	start_controller s11 --mode bundles --overall-timeout 240s --expect-alert DRIFT --alert-timeout 180s
	start_unit || ok=false
	# relayd's startup reconcile runs first and finds Tetragon in sync.
	wait_journal_step session_connected 30 || ok=false
	sleep 10
	victim=$(loaded_names | tr ',' '\n' | grep '^e3-s10-v' | head -1)
	echo "loaded before the delete: $(loaded_names); victim: ${victim}"
	if [ -z "${victim}" ]; then
		echo "no relay-managed e3-s10 policy is loaded" >&2
		ok=false
	else
		"${BIN_DIR}/e3tetra" --mode=delete --tetragon-binary "${TETRAGON_BIN}" --policy-name "${victim}" --domain relay-managed || ok=false
		echo "loaded after the delete: $(loaded_names)"
	fi
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s11.log
	reloaded=false
	for _ in $(seq 1 30); do
		if [ -n "${victim}" ] && loaded_names | tr ',' '\n' | grep -qx "${victim}"; then
			reloaded=true
			break
		fi
		sleep 1
	done
	echo "loaded after the re-assert: $(loaded_names)"
	[ "${reloaded}" = true ] || { echo "${victim} was not loaded again" >&2; ok=false; }
	# The policy is back within milliseconds of the re-assert's add, before
	# relayd's own check-and-audit completes (run 45941496156 grepped too
	# early), so wait for the records rather than reading the journal once.
	wait_journal_step drift_detected 30 || ok=false
	wait_journal_step drift_reasserted 30 || ok=false
	scenario_journal
	stop_unit
	record_result S11 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S12: an enforce bundle that SIGKILLs an admin-path process (the real
# /usr/bin/bash, apply's compiled-in admin-path list) inside this
# scenario's own process tree (matchPIDs, followForks; never any other
# bash on the runner) fails the health window and rolls back:
# ApplyResult ROLLED_BACK. G5 needs the same policy name in monitor mode
# first (APPLIED). The trigger shell only uses builtins until told to go,
# 35 s after the enforce bundle was sent, so heartbeats are seen during
# the health window before the kill.
# ---------------------------------------------------------------------
admin_kill_policy() {
	cat <<POLICY
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "e3-admin-kill"
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "/usr/bin/bash"
        matchPIDs:
        - operator: "In"
          followForks: true
          isNamespacePID: false
          values:
          - $1
        matchActions:
        - action: "Sigkill"
POLICY
}

scenario_s12() {
	log "S12: enforce bundle kills an admin-path process -> ROLLED_BACK, heartbeats continue"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	go_file=/tmp/e3-s12-go
	fifo=/tmp/e3-s12-fifo
	rm -f "${go_file}" "${fifo}"
	mkfifo "${fifo}"
	# Builtins only (read -t on a FIFO nobody writes; [ -e ]) until the go
	# file exists, then two external commands: this /usr/bin/bash becomes
	# the caller of an exec (ADR 0020) and is killed by the enforce policy.
	/usr/bin/bash -c "exec 9<>'${fifo}'; until [ -e '${go_file}' ]; do read -r -t 1 -u 9 _ || :; done; /usr/bin/true; /usr/bin/true" &
	trigger_pid=$!
	echo "S12 trigger shell pid: ${trigger_pid}"
	admin_kill_policy "${trigger_pid}" >"${BUNDLE_DIR}/e3-admin-kill.yaml"
	sign_bundle "${BUNDLE_DIR}/s12-monitor.json" "${E3_KEYS}/v3/targets.key" 5 monitor "e3-admin-kill=${BUNDLE_DIR}/e3-admin-kill.yaml" || ok=false
	sign_bundle "${BUNDLE_DIR}/s12-enforce.json" "${E3_KEYS}/v3/targets.key" 6 enforce "e3-admin-kill=${BUNDLE_DIR}/e3-admin-kill.yaml" || ok=false
	start_controller s12 --mode bundles --overall-timeout 420s --apply-timeout 180s \
		--min-heartbeats-during-apply 2 \
		--bundle "${BUNDLE_DIR}/s12-monitor.json" --expect APPLIED \
		--bundle "${BUNDLE_DIR}/s12-enforce.json" --expect ROLLED_BACK
	start_unit || ok=false
	for _ in $(seq 1 200); do
		grep -q 'sent bundle 2' /tmp/e3controller-s12.log && break
		sleep 1
	done
	sleep 35
	touch "${go_file}"
	trigger_rc=0
	wait "${trigger_pid}" || trigger_rc=$?
	echo "S12 trigger shell exit status: ${trigger_rc} (137 = SIGKILL)"
	[ "${trigger_rc}" = 137 ] || { echo "the admin-path shell was not killed" >&2; ok=false; }
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s12.log
	journal=$(scenario_journal)
	echo "${journal}"
	grep '"step":"health_window_failed"' <<<"${journal}" | grep -q 'admin_path_enforcement_event' || { echo "no admin-path health-window failure in the journal" >&2; ok=false; }
	grep -q '"step":"rolled_back"' <<<"${journal}" || ok=false
	stop_unit
	rm -f "${fifo}"
	record_result S12 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# Step 7a telemetry scenarios (T-S1..T-S5). relayd runs the real unit
# with the e3 drop-in, talking to cmd/e3collector on 127.0.0.1:18444
# (inside the drop-in's IPAddressAllow). The collector appends every batch
# to a store file before acking it; `e3collector report` re-runs the
# reference verifier over that file.
# ---------------------------------------------------------------------
start_collector() {
	local name="$1" store="$2"
	shift 2
	"${BIN_DIR}/e3collector" serve --listen "${COLLECTOR_ADDR}" --ca-cert "${CA_CERT}" \
		--cert "${COLLECTOR_CERT}" --key "${COLLECTOR_KEY}" --trust-domain "${TRUST_DOMAIN}" \
		--store "${store}" "$@" >>"/tmp/e3collector-${name}.log" 2>&1 &
	coll_pid=$!
	sleep 1
}

stop_collector() {
	kill "${coll_pid}" 2>/dev/null || true
	wait "${coll_pid}" 2>/dev/null || true
}

collector_report() {
	"${BIN_DIR}/e3collector" report --store "$1" --host-uuid "${HOST_UUID}" "${@:2}"
}

spool_batches() {
	sudo find "${SPOOL_DIR}" -maxdepth 1 -name '*.batch' | wc -l
}

# wait_spool_empty SECONDS: every spooled batch acked and deleted.
wait_spool_empty() {
	for _ in $(seq 1 "$1"); do
		[ "$(spool_batches)" = 0 ] && return 0
		sleep 1
	done
	echo "spool still holds $(spool_batches) batch(es)" >&2
	return 1
}

# events_for SECONDS: exec events (non_security) every 0.3 s, plus a
# kprobe event (security) every second through the baseline policy's
# Post action on /tmp/e3-baseline-placeholder.
events_for() {
	local end=$((SECONDS + $1))
	while [ "${SECONDS}" -lt "${end}" ]; do
		/usr/bin/true
		/tmp/e3-baseline-placeholder -c '/usr/bin/true; /usr/bin/true' 2>/dev/null || true
		sleep 0.3
	done
}

TS_STORE=${COLLECTOR_DIR}/ts123.jsonl

# T-S1: events arrive with a valid chain; a canary exec shows up with argv
# redacted, no environment, and a hashed ~/.ssh path. The spool is emptied
# first (harness setup, like S13's store restore) so the collector sees
# the chain from seq 1.
scenario_ts1() {
	log "T-S1: valid chain; canary exec redacted (argv, env, ~/.ssh)"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	stop_unit
	sudo find "${SPOOL_DIR}" -mindepth 1 -delete
	rm -f "${TS_STORE}"
	sudo install -o root -g root -m 0755 /usr/bin/bash /tmp/e3-baseline-placeholder
	sudo mkdir -p /home/e3canary/.ssh
	sudo chmod 0755 /home/e3canary /home/e3canary/.ssh
	start_collector ts "${TS_STORE}"
	start_controller ts1 --mode steady --min-heartbeats 3 --heartbeat-deadline 90s
	start_unit || ok=false
	sleep 3
	# The canary: cwd under ~/.ssh, a ~/.ssh path, a password and a token
	# in argv, and a secret in the environment.
	# (The environment variable is set without sudo/env, so the secret is
	# in the process environment only, never in anyone's argv.)
	E3_SECRET_ENV=e3-env-secret sh -c 'cd /home/e3canary/.ssh && /usr/bin/cat /home/e3canary/.ssh/id_e3 --password=hunter2 token=e3tok >/dev/null 2>&1' || true
	/tmp/e3-baseline-placeholder -c '/usr/bin/true; /usr/bin/true' || true
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-ts1.log
	wait_spool_empty 60 || ok=false
	rep=$(collector_report "${TS_STORE}" --decode) || ok=false
	echo "${rep}"
	grep -q 'event .*ProcessExec.*binary="/usr/bin/cat"' <<<"${rep}" || { echo "canary exec not in telemetry" >&2; ok=false; }
	grep -q 'ProcessKprobe' <<<"${rep}" || { echo "no security (kprobe) event in telemetry" >&2; ok=false; }
	grep 'binary="/usr/bin/cat"' <<<"${rep}" | grep -q '\[REDACTED\]' || { echo "argv not redacted" >&2; ok=false; }
	grep 'binary="/usr/bin/cat"' <<<"${rep}" | grep -q 'sha256:' || { echo "~/.ssh path not hashed" >&2; ok=false; }
	if grep -E 'hunter2|e3tok|/home/e3canary/\.ssh|e3-env-secret' <<<"${rep}"; then
		echo "a secret or ~/.ssh path reached the collector" >&2
		ok=false
	fi
	if grep -E 'event .* env=[1-9]' <<<"${rep}"; then
		echo "an event carries environment variables" >&2
		ok=false
	fi
	grep -qE 'telemetry_last_seq=[1-9]' /tmp/e3controller-ts1.log || { echo "heartbeat telemetry_last_seq never set" >&2; ok=false; }
	scenario_journal
	record_result T-S1 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# T-S2: the collector is down for 30 s while events flow: the spool grows
# and the heartbeat's telemetry_backlog rises; after it is back, everything
# drains in order, the verifier reports no gap, and the spool empties.
# relayd keeps running from T-S1.
scenario_ts2() {
	log "T-S2: collector outage of 30 s; spool grows, backlog rises, drains in order"
	ok=true
	start_controller ts2 --mode steady --min-heartbeats 4 --heartbeat-deadline 120s
	stop_collector
	before=$(spool_batches)
	events_for 30
	during=$(spool_batches)
	echo "T-S2 spool batches: before outage=${before} after 30 s down=${during}"
	[ "${during}" -gt "${before}" ] || { echo "spool did not grow during the outage" >&2; ok=false; }
	start_collector ts "${TS_STORE}"
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-ts2.log
	grep -qE 'telemetry_backlog=([2-9]|[1-9][0-9]+)' /tmp/e3controller-ts2.log || { echo "telemetry_backlog never rose in a heartbeat" >&2; ok=false; }
	wait_spool_empty 90 || ok=false
	rep=$(collector_report "${TS_STORE}") || ok=false
	grep -E 'REPORT (chain|CLEAN|chain_gap)' <<<"${rep}"
	grep -q 'chain_reorder\|chain_gap' <<<"${rep}" && { echo "reorder or gap after the outage" >&2; ok=false; }
	grep -q 'telemetry_stream_ended' <<<"$(scenario_journal)" || { echo "the outage was not visible in the journal" >&2; ok=false; }
	sudo systemctl is-active --quiet "${UNIT}" || { echo "relayd stopped during the collector outage" >&2; ok=false; }
	[ "$(systemctl show "${UNIT}" -p NRestarts --value)" = 0 ] || { echo "relayd restarted during the collector outage" >&2; ok=false; }
	record_result T-S2 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# T-S3: restart relayd mid-stream: the chain continues (same chain_id,
# seq + 1, prev_hash matches), which the verifier checks over the whole
# store: one chain, contiguous, clean.
scenario_ts3() {
	log "T-S3: relayd restart mid-stream continues the chain"
	ok=true
	events_for 5 &
	gen_pid=$!
	sleep 2
	SCENARIO_SINCE=$(date '+%Y-%m-%d %H:%M:%S')
	sudo systemctl restart "${UNIT}" || ok=false
	wait "${gen_pid}"
	events_for 5
	wait_spool_empty 60 || ok=false
	stop_collector
	rep=$(collector_report "${TS_STORE}") || ok=false
	grep -E 'REPORT (chain|CLEAN|chain_)' <<<"${rep}"
	[ "$(grep -c '^REPORT chain [0-9a-f]' <<<"${rep}")" = 1 ] || { echo "the restart started a new chain" >&2; ok=false; }
	grep -q '"step":"telemetry_chain_continued"' <<<"$(scenario_journal)" || { echo "no telemetry_chain_continued record after the restart" >&2; ok=false; }
	stop_unit
	record_result T-S3 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# P4-RSS (step 7b P4/Z4): relayd under the real unit at a sustained event
# rate. P4_LOOPS shell loops exec /usr/bin/true for 60 s (each exec is an
# exec and an exit event). Records relayd's VmRSS every second (max must stay
# < 64 MiB with the unit's MemoryMax untouched), relayd's own CPU per event
# (utime+stime from /proc, so this includes gRPC decode and TLS, which the
# benchmark does not), the events the collector received, and the
# compression ratio on these real events. It runs after T-S5, which leaves
# the unit and the collector stopped with the e3 drop-in in place: P4
# starts both and stops both again at the end. The load loops run with xtrace off (the job runs under set -x, which
# would otherwise throttle them and flood the log).
P4_LOOPS=${P4_LOOPS:-2}
scenario_p4_rss() {
	log "P4-RSS: relayd RSS and CPU at a sustained event rate (${P4_LOOPS} exec loops, 60 s)"
	ok=true
	local store=${COLLECTOR_DIR}/p4.jsonl pid clk t0 t1 c0 c1 maxrss=0 rss n1 sent decoded zb
	stop_collector
	rm -f "${store}"
	# A fresh chain (harness setup, as in T-S1/T-S4), so the collector
	# sees it from seq 1 and the verifier can check it whole.
	sudo find "${SPOOL_DIR}" -mindepth 1 -delete
	start_collector p4 "${store}"
	start_unit || ok=false
	sleep 5
	wait_spool_empty 60 || true
	pid=$(systemctl show "${UNIT}" -p MainPID --value)
	if [ "${pid}" = 0 ] || [ ! -r "/proc/${pid}/stat" ]; then
		echo "relayd is not running (MainPID=${pid})" >&2
		stop_collector
		record_result P4-RSS FAIL
		return
	fi
	clk=$(getconf CLK_TCK)
	echo "P4-RSS unit MemoryMax=$(systemctl show "${UNIT}" -p MemoryMax --value) MainPID=${pid}"
	grep -E 'VmRSS|VmHWM' "/proc/${pid}/status"
	c0=$(awk '{print $14 + $15}' "/proc/${pid}/stat")
	t0=$(date +%s.%N)
	local loops=()
	for _ in $(seq 1 "${P4_LOOPS}"); do
		(set +x; end=$((SECONDS + 60)); while [ "${SECONDS}" -lt "${end}" ]; do /usr/bin/true; done) &
		loops+=($!)
	done
	for _ in $(seq 1 60); do
		rss=$(awk '/^VmRSS:/ {print $2}' "/proc/${pid}/status" 2>/dev/null || echo 0)
		[ "${rss:-0}" -gt "${maxrss}" ] && maxrss=${rss}
		sleep 1
	done
	# Only the load loops: a bare wait would also wait for the collector
	# and controller, which never exit.
	wait "${loops[@]}"
	t1=$(date +%s.%N)
	c1=$(awk '{print $14 + $15}' "/proc/${pid}/stat")
	wait_spool_empty 120 || ok=false
	grep -E 'VmRSS|VmHWM' "/proc/${pid}/status"
	rep=$(collector_report "${store}" --decode) || ok=false
	grep -E 'REPORT (chain|CLEAN)' <<<"${rep}"
	n1=$(grep -o '"kind":"events","class":"[a-z_]*","count":[0-9]*' <<<"${rep}" | awk -F: '{s += $NF} END {print s + 0}')
	read -r sent decoded zb < <(grep '^REPORT   events enc=' <<<"${rep}" | awk '{for (i = 1; i <= NF; i++) {split($i, kv, "="); v[kv[1]] = kv[2]} s += v["sent"]; d += v["decoded"]; if (v["enc"] == "zstd") z++} END {print s + 0, d + 0, z + 0}')
	awk -v c0="${c0}" -v c1="${c1}" -v clk="${clk}" -v t0="${t0}" -v t1="${t1}" -v n="${n1}" -v m="${maxrss}" -v s="${sent}" -v d="${decoded}" -v z="${zb}" 'BEGIN {
		cpu = (c1 - c0) / clk; wall = t1 - t0
		printf "P4-RSS events=%d wall=%.1fs rate=%.0f/s relayd_cpu=%.2fs (%.2f%% of one core) cpu_per_event=%.0fns max_vmrss=%.1fMiB\n", n, wall, n / wall, cpu, 100 * cpu / wall, (n > 0 ? 1e9 * cpu / n : 0), m / 1024
		if (s > 0) printf "P4-RSS payload sent=%d decoded=%d ratio=%.2f zstd_batches=%d sent_B/event=%.0f decoded_B/event=%.0f\n", s, d, d / s, z, s / n, d / n
	}'
	[ "${n1}" -gt 10000 ] || { echo "too few events (${n1}) for a sustained-rate measurement" >&2; ok=false; }
	[ "${maxrss}" -lt $((64 * 1024)) ] || { echo "relayd VmRSS reached ${maxrss} KiB (>= 64 MiB)" >&2; ok=false; }
	[ "$(systemctl show "${UNIT}" -p MainPID --value)" = "${pid}" ] || { echo "relayd restarted under load" >&2; ok=false; }
	# Observation for T-S6 (not a pass criterion): does Tetragon still
	# deliver events to this relayd 10 s after the flood, and to a fresh
	# one? In run 46051067160 the next scenarios received none.
	local before after
	before=$(grep -c . "${store}" 2>/dev/null || echo 0)
	events_for 10
	sleep 3
	after=$(grep -c . "${store}" 2>/dev/null || echo 0)
	echo "P4-RSS after the flood: collector store lines ${before} -> ${after} over 10 s of events (same relayd)"
	sudo systemctl restart "${UNIT}" || true
	sleep 5
	before=${after}
	events_for 10
	sleep 3
	after=$(grep -c . "${store}" 2>/dev/null || echo 0)
	echo "P4-RSS after the flood: collector store lines ${before} -> ${after} over 10 s of events (restarted relayd)"
	stop_unit
	stop_collector
	record_result P4-RSS "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# T-S4: a tiny spool cap. 64 KiB since step 7b: events are now
# zstd-compressed (about 4.5x), and 43 s of E3 events fit in 90,776 bytes
# (run 46039848254), so 7a's 512 KiB never overflowed. The only difference
# is collector.spool_max_bytes = 65536, in a copy of relay.yaml that a
# second drop-in line points ExecStart at. With the collector down, non_security batches are
# dropped first, a dropped record appears in the chain, and security
# events survive.
scenario_ts4() {
	log "T-S4: tiny spool cap; non_security dropped first, declared, security survives"
	ok=true
	local small=/etc/tetragon-relay/relay-ts4.yaml store="${COLLECTOR_DIR}/ts4.jsonl"
	sudo sed 's/^collector:$/collector:\n  spool_max_bytes: 65536/' "${RELAY_YAML}" | sudo tee "${small}" >/dev/null
	sudo chown root:tetragon-relay "${small}"
	sudo chmod 0640 "${small}"
	diff "${RELAY_YAML}" "${small}" || true
	write_dropins "e3.conf=$(e3_dropin)" "ts4.conf=$(printf '[Service]\nExecStart=\nExecStart=%s/relayd-e3 --config %s' "${RELAYD_DIR}" "${small}")"
	sudo find "${SPOOL_DIR}" -mindepth 1 -delete
	rm -f "${store}"
	start_unit || ok=false
	events_for 3 # a few security events first: they must survive
	events_for 40
	echo "T-S4 spool: $(spool_batches) batches, $(sudo du -sb "${SPOOL_DIR}" | cut -f1) bytes"
	start_collector ts4 "${store}"
	wait_spool_empty 90 || ok=false
	stop_collector
	rep=$(collector_report "${store}" --decode) || ok=false
	grep -E 'REPORT (chain|CLEAN|chain_)|dropped' <<<"${rep}" | head -40
	grep -q 'dropped(class=non_security' <<<"${rep}" || { echo "no non_security dropped record in the chain" >&2; ok=false; }
	grep -q 'dropped(class=security' <<<"${rep}" && { echo "security batches were dropped" >&2; ok=false; }
	grep -q 'ProcessKprobe' <<<"${rep}" || { echo "no security event survived" >&2; ok=false; }
	grep -q '"step":"telemetry_batches_dropped"' <<<"$(scenario_journal)" || ok=false
	stop_unit
	write_dropins "e3.conf=$(e3_dropin)"
	sudo rm -f "${small}"
	record_result T-S4 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# T-S5: the collector acks a seq never sent. relayd audits the protocol
# error, reconnects and resends; it deletes nothing early, which shows as
# the hostilely acked batch arriving again (an identical duplicate).
scenario_ts5() {
	log "T-S5: hostile ack -> audited, reconnect, resend, nothing deleted early"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	local store="${COLLECTOR_DIR}/ts5.jsonl"
	rm -f "${store}"
	sudo find "${SPOOL_DIR}" -mindepth 1 -delete
	start_collector ts5 "${store}" --hostile-ack-once
	start_unit || ok=false
	events_for 10
	wait_spool_empty 60 || ok=false
	stop_collector
	cat /tmp/e3collector-ts5.log | grep -E 'HOSTILE|stream #' || true
	grep -q 'HOSTILE ack' /tmp/e3collector-ts5.log || ok=false
	grep -q 'stream #2' /tmp/e3collector-ts5.log || { echo "relayd did not reconnect after the hostile ack" >&2; ok=false; }
	grep -q '"step":"telemetry_protocol_error"' <<<"$(scenario_journal)" || { echo "hostile ack not audited" >&2; ok=false; }
	rep=$(collector_report "${store}") || ok=false
	grep -E 'REPORT (chain|CLEAN|chain_)' <<<"${rep}"
	grep -q 'duplicate(identical resend)' <<<"${rep}" || { echo "nothing was resent: the hostile ack may have deleted batches" >&2; ok=false; }
	stop_unit
	record_result T-S5 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# ---------------------------------------------------------------------
# S13 (step 7a A4, ADR 0038): tampered mode. With relayd stopped, one
# hex digit of the store index's HMAC is changed in place (same file,
# owner and mode), so store.Open reports HMAC mismatch -> TAMPERED.
# relayd must start (READY=1, no restart loop), send Alert{TAMPER} as its
# first message, heartbeat with an empty epochs map, answer a bundle
# REJECTED_TAMPERED and a TrustUpdate with TRUST_UPDATE_REJECTED, leave
# Tetragon's loaded set unchanged, and never die of SIGSYS. The original
# index is restored afterwards so S4 runs on an intact store.
# ---------------------------------------------------------------------
scenario_s13() {
	log "S13: store index tampered while stopped -> tampered mode: TAMPER, empty epochs, REJECTED_TAMPERED"
	write_dropins "e3.conf=$(e3_dropin)"
	ok=true
	stop_unit
	sudo cp -p "${STORE_DIR}/index" /var/tmp/e3-s13-index.bak || ok=false
	sudo python3 - "${STORE_DIR}/index" <<'PY' || ok=false
import sys
p = sys.argv[1]
s = open(p).read()
i = s.index('"hmac":"') + len('"hmac":"')
s = s[:i] + ('1' if s[i] != '1' else '2') + s[i + 1:]
with open(p, 'r+') as f:  # same inode, owner and mode
    f.write(s)
PY
	sudo ls -l "${STORE_DIR}/index"
	before=$(loaded_names)
	start_controller s13 --mode tampered --min-heartbeats 2 --overall-timeout 150s --apply-timeout 30s --alert-timeout 30s \
		--bundle "${BUNDLE_DIR}/s12-monitor.json" --expect REJECTED_TAMPERED \
		--trust-update "${BUNDLE_DIR}/root-v2.json"
	start_unit || ok=false
	wait "${ctrl_pid}" || ok=false
	cat /tmp/e3controller-s13.log
	check_loaded_unchanged "${before}" || ok=false
	journal=$(scenario_journal)
	echo "${journal}"
	grep -q '"step":"tampered_mode"' <<<"${journal}" || { echo "no tampered_mode record" >&2; ok=false; }
	grep -q 'HMAC mismatch' <<<"${journal}" || { echo "tamper reason is not the HMAC mismatch" >&2; ok=false; }
	if grep -E 'status=31/SYS|code=dumped' <<<"${journal}"; then
		echo "relayd died (SIGSYS or core dump) in tampered mode" >&2
		ok=false
	fi
	restarts=$(systemctl show "${UNIT}" -p NRestarts --value)
	echo "S13 NRestarts=${restarts}"
	[ "${restarts}" = 0 ] || { echo "relayd restarted in tampered mode" >&2; ok=false; }
	stop_unit
	sudo cp -p /var/tmp/e3-s13-index.bak "${STORE_DIR}/index" || ok=false
	record_result S13 "$([ "${ok}" = true ] && echo PASS || echo FAIL)"
}

# no_sigsys_in_job: step 7a: no SIGSYS anywhere in the job. Every
# syscall relayd makes must be allowed by the unit as shipped.
no_sigsys_in_job() {
	local j
	j=$(sudo journalctl -u "${UNIT}" --since "${JOB_SINCE}" --no-pager)
	if grep -E 'status=31/SYS' <<<"${j}"; then
		record_result NO_SIGSYS FAIL
	else
		record_result NO_SIGSYS PASS
	fi
}

main() {
	JOB_SINCE=$(date '+%Y-%m-%d %H:%M:%S')
	setup_users_and_dirs
	write_relay_yaml
	write_throwaway_ca
	write_root_json
	preload_baseline_policy
	install_unit

	if ! start_swtpm_chardev; then
		echo "no /dev/tpmrm0; every scenario needs it" >&2
		for s in S1 S2 S3 S4 S5 S6 S7 S8 S9 S10 S11 S12 S13 T-S1 T-S2 T-S3 P4-RSS T-S4 T-S5; do record_result "${s}" FAIL; done
	else
		# C5: the two identity-free scenarios first, then testenroll,
		# then the identity scenarios.
		scenario_s1
		scenario_s2
		if run_testenroll; then
			scenario_s3
			scenario_s5
			scenario_s6
			scenario_s7
			scenario_s8
			scenario_s9 # needs S7's bundle and persisted epoch
			scenario_s10
			scenario_s11 # needs S10's relay-managed e3-s10
			scenario_s12
			scenario_ts1
			scenario_ts2 # needs T-S1's relayd and collector store
			scenario_ts3 # needs T-S2's
			scenario_ts4
			scenario_ts5
			# Last of the telemetry scenarios: after its flood, Tetragon
			# delivered no events to T-S4/T-S5 (run 46051067160).
			scenario_p4_rss
			scenario_s13 # needs S10's root-v2.json and S12's bundle; restores the index
			scenario_s4  # last: revocation is terminal for this store (ADR 0035)
		else
			for s in S3 S4 S5 S6 S7 S8 S9 S10 S11 S12 S13 T-S1 T-S2 T-S3 P4-RSS T-S4 T-S5; do record_result "${s}" FAIL; done
		fi
		write_dropins
		no_sigsys_in_job
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

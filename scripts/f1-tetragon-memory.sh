#!/usr/bin/env bash
# F1 (docs/reviews/step-07b-decisions-3.md): Tetragon v1.8.0's memory under
# an exec flood. REPORT ONLY: this script never fails on what it measures,
# only on harness errors.
#
# Each round starts Tetragon (a transient root unit, as in the integration
# job) with one extra setting, loads a Sigkill canary policy, starts a
# GetEvents client (e3tetra drain, paced like relayd at its quota or like
# T-S6's slow client), floods exec for F1_FLOOD_SECS with cmd/e3execflood,
# samples Tetragon's VmRSS every 10 s, and runs the canary 60 s in: 137
# means enforcement still works.
#
# The flags tried are the ones the binary's own --help lists whose names
# bound a queue, cache or buffer and take an integer with a default; each
# is set to its default / 16 (at least 64). Nothing is guessed: a flag
# that isn't in --help isn't tried.
#
# Needs: TETRAGON_BIN, BIN_DIR (e3tetra, e3execflood), the tetragon-relay
# group for the socket (run under sg tetragon-relay), passwordless sudo.
set -uo pipefail

F1_FLOOD_SECS=${F1_FLOOD_SECS:-180}
F1_WORKERS=${F1_WORKERS:-4}
F1_CLIENT_RATE=${F1_CLIENT_RATE:-2000} # P5: relayd delivered about 2,000 msgs/s at its quota
SOCK=/var/run/tetragon/tetragon.sock
TP_DIR=/tmp/f1-tp.d
CANARY=/usr/local/bin/f1-canary
BPF_LIB="$(dirname "${TETRAGON_BIN}")/../lib/tetragon/bpf"

log() { printf '\n== %s ==\n' "$*"; }

stop_tetragon() {
	sudo systemctl stop tetragon.service 2>/dev/null || true
	sudo systemctl reset-failed tetragon.service 2>/dev/null || true
	for _ in $(seq 1 30); do
		systemctl is-active --quiet tetragon.service || return 0
		sleep 1
	done
}

start_tetragon() {
	stop_tetragon
	sudo rm -f "${SOCK}"
	sudo systemd-run --unit=tetragon --collect --property=Type=simple \
		"${TETRAGON_BIN}" --server-address "unix://${SOCK}" --tracing-policy-dir "${TP_DIR}" \
		--bpf-lib "${BPF_LIB}" --metrics-server 127.0.0.1:2112 "$@" >/dev/null
	for _ in $(seq 1 60); do
		[ -S "${SOCK}" ] && break
		sleep 1
	done
	if [ ! -S "${SOCK}" ]; then
		echo "Tetragon did not start with: $*" >&2
		sudo journalctl -u tetragon.service --no-pager | tail -20 >&2
		return 1
	fi
	sudo chmod 660 "${SOCK}"
	sudo chown root:tetragon-relay "${SOCK}"
	sleep 2
}

tetragon_rss() { awk '/^VmRSS:/ {print $2}' "/proc/$(systemctl show tetragon.service -p MainPID --value)/status" 2>/dev/null || echo 0; }
tetragon_overflow() { curl -fsS --max-time 5 http://127.0.0.1:2112/metrics 2>/dev/null | awk '$1 == "tetragon_notify_overflowed_events_total" {print $2}' | head -1; }

run_canary() {
	local rc=0
	timeout 20 "${CANARY}" -c "/usr/bin/true; /usr/bin/true" || rc=$?
	echo "${rc}"
}

# round NAME CLIENT_RATE [TETRAGON FLAGS...]
round() {
	local name="$1" rate="$2" t rss rc="-" series="" max=0 first=0 at120=0 last=0 ov0 ov1 drain_pid flood_pid
	shift 2
	log "F1 round ${name}: client ${rate} msgs/s, Tetragon $*"
	if ! start_tetragon "$@"; then
		echo "F1 ${name}: Tetragon did not start (flag rejected?)"
		return 0
	fi
	"${BIN_DIR}/e3tetra" --mode=add --file /tmp/f1-kill.yaml --tetragon-binary "${TETRAGON_BIN}" || { echo "F1 ${name}: policy load failed"; return 0; }
	"${BIN_DIR}/e3tetra" --mode=drain --duration "$((F1_FLOOD_SECS + 20))s" --rate "${rate}" --tetragon-binary "${TETRAGON_BIN}" >/tmp/f1-drain.out 2>&1 &
	drain_pid=$!
	sleep 5
	ov0=$(tetragon_overflow)
	first=$(tetragon_rss)
	"${BIN_DIR}/e3execflood" --workers "${F1_WORKERS}" --duration "${F1_FLOOD_SECS}s" >/tmp/f1-flood.out 2>&1 &
	flood_pid=$!
	for t in $(seq 10 10 "${F1_FLOOD_SECS}"); do
		sleep 10
		rss=$(tetragon_rss)
		series="${series} ${t}s=$((rss / 1024))M"
		[ "${rss}" -gt "${max}" ] && max=${rss}
		[ "${t}" = 60 ] && rc=$(run_canary)
		[ "${t}" = 120 ] && at120=${rss}
		last=${rss}
	done
	wait "${flood_pid}" || true
	wait "${drain_pid}" || true
	ov1=$(tetragon_overflow)
	cat /tmp/f1-flood.out
	cat /tmp/f1-drain.out
	echo "F1 ${name} VmRSS:${series}"
	awk -v n="${name}" -v f="${first}" -v m="${max}" -v a="${at120}" -v l="${last}" -v rc="${rc}" -v o0="${ov0:-0}" -v o1="${ov1:-0}" 'BEGIN {
		g = (a > 0) ? 100 * (l - a) / a : 0
		printf "F1 RESULT %s: rss_before=%dM rss_max=%dM rss_end=%dM growth_last_60s=%.1f%% plateau=%s canary_rc=%s (137 = killed) notify_overflowed=+%d\n", n, f / 1024, m / 1024, l / 1024, g, (g < 5 && g > -50) ? "yes" : "no", rc, o1 - o0
	}'
	stop_tetragon
}

main() {
	mkdir -p "${TP_DIR}"
	sudo install -o root -g root -m 0755 /usr/bin/bash "${CANARY}"
	cat >/tmp/f1-kill.yaml <<POLICY
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "f1-canary-kill"
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "${CANARY}"
        matchActions:
        - action: "Sigkill"
POLICY

	log "F1: Tetragon v1.8.0 flags that bound a queue, cache or buffer (tetragon --help)"
	local help flags=() line flag def
	help=$("${TETRAGON_BIN}" --help 2>&1)
	grep -E -- '--[a-z0-9-]*(queue|cache|buffer|rb-|ring|-size|limit|gc-|memory)[a-z0-9-]*' <<<"${help}" | sed 's/^/F1 HELP /'
	# F2's question: can Tetragon serve its metrics on a unix socket?
	grep -iE -- 'metrics|server-address|health-server' <<<"${help}" | sed 's/^/F2 METRICS HELP /'
	# Integer flags with a default whose name says queue/cache/buffer size.
	while IFS= read -r line; do
		flag=$(sed -n 's/^ *\(--[a-z0-9-]*\) int .*/\1/p' <<<"${line}")
		def=$(sed -n 's/.*(default \([0-9][0-9]*\)).*/\1/p' <<<"${line}")
		[ -n "${flag}" ] && [ -n "${def}" ] && [ "${def}" -gt 0 ] || continue
		flags+=("${flag}=$(((def / 16) > 64 ? def / 16 : 64))")
		echo "F1 CANDIDATE ${flag} default=${def} tried=$(((def / 16) > 64 ? def / 16 : 64))"
	done < <(grep -E -- '--[a-z0-9-]*(queue|cache|buffer)[a-z0-9-]*(-size)? int ' <<<"${help}")

	round baseline-slow-client 100
	round baseline "${F1_CLIENT_RATE}"
	local f
	for f in "${flags[@]}"; do
		round "${f}" "${F1_CLIENT_RATE}" "${f}"
	done

	log "F1 summary (report only)"
	echo "see the F1 RESULT lines above"
}

main "$@"

#!/usr/bin/env bash
# Step 7b P1/P3: the telemetry pipeline benchmark, its per-stage
# breakdown, CPU and allocation profiles, and the CPU gate.
#
#   scripts/bench-gate.sh [out-dir]
#
# Gate: BenchmarkPipeline5k's cpu-ns/event (process CPU over the measured
# window / events; scripts and harness do no work in it) must be
# <= BENCH_GATE_NS (6000 ns = 3 % of one core at 5k events/s) in EVERY one
# of BENCH_GATE_RUNS runs: the worst run is gated, not the best.
set -euo pipefail

out=${1:-bench-out}
gate_ns=${BENCH_GATE_NS:-6000}
runs=${BENCH_GATE_RUNS:-3}
events=${BENCH_EVENTS:-200000}
mkdir -p "$out"

go test -c -o "$out/telemetry.test" ./internal/telemetry
t="$out/telemetry.test"

echo "== machine"
uname -a
grep -m1 'model name' /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null || true
nproc 2>/dev/null || true

# Same-machine history (step 7b P2: before and after each change). GitHub's
# runners are not one CPU model, so numbers from different runs do not
# compare; BENCH_HISTORY="ref:label ..." builds each ref's benchmark and runs
# them all here, on this machine, one after another.
if [ -n "${BENCH_HISTORY:-}" ]; then
	echo "== same-machine history: $BENCH_HISTORY"
	: >"$out/history.txt"
	for item in $BENCH_HISTORY; do
		ref=${item%%:*}
		label=${item#*:}
		src="$out/src-$ref"
		rm -rf "$src"
		git worktree add -f --detach "$src" "$ref" >/dev/null 2>&1
		(cd "$src" && go test -c -o "../history-$ref.test" ./internal/telemetry) >/dev/null
		git worktree remove -f "$src"
		h="$out/history-$ref.test"
		{
			echo "### $label ($ref)"
			"$h" -test.run=NONE -test.bench='^BenchmarkStage(Decode|Redact|Marshal)$' -test.benchtime=50000x | grep '^Benchmark' || true
			"$h" -test.run=NONE -test.bench='^BenchmarkStage(Spool|Compress)$' -test.benchtime=300x | grep '^Benchmark' || true
			"$h" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" -test.count=2 | grep '^Benchmark' || true
		} | tee -a "$out/history.txt"
		rm -f "$h"
	done
fi

echo "== stage breakdown"
"$t" -test.run=NONE -test.bench='^BenchmarkStage(Decode|Classify|Redact|Marshal)$' -test.benchtime=50000x | tee "$out/stages.txt"
"$t" -test.run=NONE -test.bench='^BenchmarkStage(Spool|Compress)$' -test.benchtime=300x | tee -a "$out/stages.txt"

echo "== profiled pipeline runs ($events events; CPU and allocation profiles in separate runs so one does not distort the other)"
"$t" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" -test.cpuprofile "$out/cpu.out" | tee "$out/profiled.txt"
"$t" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" -test.memprofile "$out/mem.out" -test.memprofilerate=4096 >/dev/null

echo "== CPU profile, pipeline goroutines only (label component=telemetry), by cumulative time"
go tool pprof -top -cum -nodecount=45 -tagfocus=component=telemetry "$t" "$out/cpu.out" 2>/dev/null | tee "$out/cpu-pipeline-cum.txt" | head -60
echo "== CPU profile, whole process (GC workers included), flat"
go tool pprof -top -nodecount=30 "$t" "$out/cpu.out" 2>/dev/null | tee "$out/cpu-all-flat.txt" | head -40
echo "== allocations (alloc_space), pipeline"
go tool pprof -top -sample_index=alloc_space -focus='Pipeline..Run' -nodecount=25 "$t" "$out/mem.out" 2>/dev/null | tee "$out/alloc.txt" | head -35

echo "== stage shares of the whole-process CPU profile"
go tool pprof -top -nodecount=1 "$t" "$out/cpu.out" 2>/dev/null | grep -m1 'Total samples' || true
for stage in \
	"decode=bytesSource" \
	"redact=Redactor" \
	"marshal=MarshalOptions" \
	"compress=zstd" \
	"spool=AppendEvents" \
	"export=exporter..session" \
	"gc-bg=gcBgMarkWorker"; do
	name=${stage%%=*}
	re=${stage#*=}
	# With -focus, the top row of -cum is the stack root: its cum% is the
	# share of ALL samples whose stack contains a function matching re.
	line=$(go tool pprof -top -cum -focus="$re" -nodecount=1 "$t" "$out/cpu.out" 2>/dev/null | awk '$1 ~ /^[0-9.]+(ms|s|us)?$/ && $5 ~ /%$/ { print $4 " " $5; exit }')
	printf '%-9s %s\n' "$name" "${line:-0%}"
done | tee "$out/stage-shares.txt"

echo "== gate: $runs unprofiled runs of $events events, each must be <= $gate_ns cpu-ns/event"
"$t" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" -test.count="$runs" | tee "$out/gate.txt"
worst=$(awk '/^BenchmarkPipeline5k/ { for (i = 1; i < NF; i++) if ($(i+1) == "cpu-ns/event") print $i }' "$out/gate.txt" | sort -n | tail -1)
if [ -z "$worst" ]; then
	echo "GATE: no cpu-ns/event measured" >&2
	exit 1
fi
printf 'GATE: worst of %s runs = %s cpu-ns/event (%.2f %% of one core at 5k events/s); limit %s\n' \
	"$runs" "$worst" "$(awk -v w="$worst" 'BEGIN { print w * 5000 / 1e7 }')" "$gate_ns"
if [ "${BENCH_GATE_ENFORCE:-1}" = 1 ] && awk -v w="$worst" -v g="$gate_ns" 'BEGIN { exit !(w > g) }'; then
	echo "GATE FAIL: pipeline CPU $worst ns/event > $gate_ns" >&2
	exit 1
fi
if [ "${BENCH_GATE_ENFORCE:-1}" = 1 ]; then echo "GATE PASS"; else echo "GATE NOT ENFORCED (BENCH_GATE_ENFORCE=0)"; fi

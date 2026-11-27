#!/usr/bin/env bash
# Step 7b P1/P3/D1: the telemetry pipeline benchmark, its per-stage
# breakdown, CPU and allocation profiles, and the CPU regression gate.
#
#   scripts/bench-gate.sh [out-dir]
#
# Gate (docs/reviews/step-07b-decisions.md D1, ADR 0041): a regression
# gate on the same machine. BENCH_GATE_REF (the commit D1 landed in) and
# HEAD are both built and run here, alternately, BENCH_GATE_RUNS times
# each. BenchmarkPipeline5k's cpu-ns/event (process CPU over the measured
# window / events) of the WORST HEAD run must be <= BENCH_GATE_RATIO
# (1.25) times the MEDIAN of the reference runs. GitHub's runners are not
# one CPU model, so an absolute threshold does not hold across runs; the
# step 7b P3 absolute gate (6000 ns) is retired by D1.
set -euo pipefail

out=${1:-bench-out}
runs=${BENCH_GATE_RUNS:-3}
gate_ref=${BENCH_GATE_REF:?BENCH_GATE_REF must name the D1 reference commit}
gate_ratio=${BENCH_GATE_RATIO:-1.25}
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
			"$h" -test.run=NONE -test.bench='^BenchmarkStage(Decode|Redact|Marshal|Rewrite)$' -test.benchtime=50000x | grep '^Benchmark' || true
			"$h" -test.run=NONE -test.bench='^BenchmarkStage(Spool|Compress)$' -test.benchtime=300x | grep '^Benchmark' || true
			"$h" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" -test.count=2 | grep '^Benchmark' || true
		} | tee -a "$out/history.txt"
		rm -f "$h"
	done
fi

echo "== stage breakdown"
"$t" -test.run=NONE -test.bench='^BenchmarkStage(Decode|Classify|Redact|Marshal|Rewrite)$' -test.benchtime=50000x | tee "$out/stages.txt"
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
	"rewrite=wireState" \
	"redact=Redactor" \
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

echo "== gate: $runs runs each of $gate_ref and HEAD, alternating; worst HEAD <= $gate_ratio x median $gate_ref"
ref_src="$out/src-gate-ref"
rm -rf "$ref_src"
git worktree add -f --detach "$ref_src" "$gate_ref" >/dev/null 2>&1
(cd "$ref_src" && go test -c -o ../gate-ref.test ./internal/telemetry) >/dev/null
git worktree remove -f "$ref_src"
: >"$out/gate.txt"
for _ in $(seq 1 "$runs"); do
	"$out/gate-ref.test" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" | grep '^Benchmark' | sed 's/^/REF  /' | tee -a "$out/gate.txt"
	"$t" -test.run=NONE -test.bench='^BenchmarkPipeline5k$' -test.benchtime="${events}x" | grep '^Benchmark' | sed 's/^/HEAD /' | tee -a "$out/gate.txt"
done
ns_of() { awk -v w="$1" '$1 == w { for (i = 2; i < NF; i++) if ($(i+1) == "cpu-ns/event") print $i }' "$out/gate.txt"; }
worst=$(ns_of HEAD | sort -n | tail -1)
ref=$(ns_of REF | sort -n | awk '{ v[NR] = $1 } END { if (NR) print v[int((NR + 1) / 2)] }')
if [ -z "$worst" ] || [ -z "$ref" ]; then
	echo "GATE: no cpu-ns/event measured (HEAD '$worst', ref '$ref')" >&2
	exit 1
fi
limit=$(awk -v r="$ref" -v k="$gate_ratio" 'BEGIN { printf "%.0f", r * k }')
printf 'GATE: worst HEAD run = %s cpu-ns/event (%.2f %% of one core at 5k events/s); median %s = %s; limit %s (x%s)\n' \
	"$worst" "$(awk -v w="$worst" 'BEGIN { print w * 5000 / 1e7 }')" "$gate_ref" "$ref" "$limit" "$gate_ratio"
if [ "${BENCH_GATE_ENFORCE:-1}" = 1 ] && awk -v w="$worst" -v l="$limit" 'BEGIN { exit !(w > l) }'; then
	echo "GATE FAIL: pipeline CPU $worst ns/event > $limit ($gate_ratio x $ref, $gate_ref on this machine)" >&2
	exit 1
fi
if [ "${BENCH_GATE_ENFORCE:-1}" = 1 ]; then echo "GATE PASS"; else echo "GATE NOT ENFORCED (BENCH_GATE_ENFORCE=0)"; fi

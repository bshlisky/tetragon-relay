package telemetry

import (
	"hash/maphash"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
)

// Estimating Tetragon's silent drops (step-07b-decisions-3.md F2; T-S6
// showed Tetragon drops for a slow client with no signal on the stream).
//
// Every ProcessExit carries its process's exec_id and start_time, the same
// as the ProcessExec that started it. ingest records each exec's exec_id
// and, for each exit, checks whether that exec was seen on this stream.
// An exit whose exec was never seen counts as one dropped exec, but only
// for processes that started after the stream began (older ones can't be
// paired). Exits never seen can't be counted reliably (long-lived
// processes), so they aren't. The count is therefore a lower bound.
//
// Fork-only children. Measured on the real v1.8.0
// (TestIntegration_ForkOnlyChildExits, run 46156508611): a child that
// forks and never execs exits with its own new exec_id, for which no exec
// is ever sent, with flags "execve" and its parent's binary copied. E3
// run 46149776060 counted those as losses ("1 of 10" while idle). So an
// unpaired exit counts only when its binary differs from its parent's: a
// fork-only child never does. Both binaries must be known (under load
// Tetragon may send none); a real exec of the parent's own binary is then
// missed. Both keep the count a lower bound.
//
// An exit never removes its exec either: entries leave only by eviction,
// which raises the floor.
//
// The pairing runs in ingest, before admission, so execs that relayd's own
// rate limit drops are still recorded as seen and never counted as
// Tetragon's loss.

const (
	// pairingCapacity bounds the exec_ids held (8 bytes of hash plus 8 of
	// start time each, about 2.5 MiB with the map and ring; at 8k execs/s
	// about 8 s of history). When it is full the
	// oldest entry is evicted and the floor moves past its start time, so
	// an exit of an evicted process is never counted: the estimate stays
	// a lower bound.
	pairingCapacity = 1 << 16
	// pairingGrace is added to the stream's start before a process counts
	// as "started after the stream began", for clock differences between
	// Tetragon's start_time and relayd's wall clock.
	pairingGrace = int64(2e9)
)

type pairEntry struct {
	key   uint64
	start int64
}

// execPairing is used by the ingest goroutine; take is called by the
// builder.
type execPairing struct {
	seed  maphash.Seed
	floor int64 // exits of processes started at or before this are not counted
	seen  map[uint64]int64
	ring  []pairEntry // insertion order, for eviction
	head  int

	mu       sync.Mutex
	missing  uint64 // exits with no exec, since the last take
	received uint64 // exec and exit events observed, since the last take
}

func newExecPairing() *execPairing {
	return &execPairing{seed: maphash.MakeSeed(), seen: make(map[uint64]int64), ring: make([]pairEntry, 0, pairingCapacity)}
}

// reset starts a new stream at nowNs: nothing seen, the floor at the
// stream's start plus the grace.
func (x *execPairing) reset(nowNs int64) {
	clear(x.seen)
	x.ring = x.ring[:0]
	x.head = 0
	x.floor = nowNs + pairingGrace
}

// observe records one raw GetEventsResponse (any event; only exec and exit
// matter).
func (x *execPairing) observe(raw []byte) {
	event, execID, start, distinct, ok := peekProcess(raw)
	if !ok {
		return
	}
	key := maphash.Bytes(x.seed, execID)
	x.mu.Lock()
	x.received++
	x.mu.Unlock()
	switch event { //nolint:exhaustive // field numbers, not an enum: only exec and exit
	case fieldProcessExec:
		if _, dup := x.seen[key]; dup {
			return
		}
		x.insert(key, start)
	case fieldProcessExit:
		if _, ok := x.seen[key]; ok {
			return
		}
		if start > x.floor && distinct {
			x.mu.Lock()
			x.missing++
			x.mu.Unlock()
		}
	}
}

func (x *execPairing) insert(key uint64, start int64) {
	if len(x.ring) < cap(x.ring) {
		x.ring = append(x.ring, pairEntry{key, start})
	} else {
		old := x.ring[x.head]
		if s, ok := x.seen[old.key]; ok && s == old.start {
			delete(x.seen, old.key)
			x.floor = max(x.floor, old.start)
		}
		x.ring[x.head] = pairEntry{key, start}
		x.head = (x.head + 1) % len(x.ring)
	}
	x.seen[key] = start
}

// take returns and clears the counts since the last take.
func (x *execPairing) take() (missing, received uint64) {
	x.mu.Lock()
	defer x.mu.Unlock()
	missing, received = x.missing, x.received
	x.missing, x.received = 0, 0
	return missing, received
}

// putBack returns a count take handed out that could not be declared.
func (x *execPairing) putBack(missing uint64) {
	x.mu.Lock()
	x.missing += missing
	x.mu.Unlock()
}

// peekProcess reads, without copying, the event field (exec or exit), its
// process's exec_id and start_time (unix nanoseconds), and whether the
// process's binary and its parent's are both known and differ (a
// fork-only child's are equal), from a
// raw GetEventsResponse. ok is false for any other event, a missing
// exec_id or start_time, or malformed bytes.
func peekProcess(raw []byte) (event protowire.Number, execID []byte, startNs int64, distinct, ok bool) {
	var body []byte
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return 0, nil, 0, false, false
		}
		raw = raw[n:]
		if (num == fieldProcessExec || num == fieldProcessExit) && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(raw)
			if m < 0 || event != 0 {
				return 0, nil, 0, false, false
			}
			event, body = num, v
			raw = raw[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return 0, nil, 0, false, false
		}
		raw = raw[m:]
	}
	if event == 0 {
		return 0, nil, 0, false, false
	}
	// ProcessExec.process and .parent, ProcessExit.process and .parent,
	// are fields 1 and 2.
	proc, found := bytesField(body, 1)
	if !found {
		return 0, nil, 0, false, false
	}
	parent, _ := bytesField(body, 2)
	bin, _ := bytesField(proc, 5) // Process.binary
	pbin, pfound := bytesField(parent, 5)
	distinct = pfound && len(bin) > 0 && len(pbin) > 0 && string(bin) != string(pbin)
	// Process.exec_id is field 1, Process.start_time field 8.
	execID, found = bytesField(proc, 1)
	if !found || len(execID) == 0 {
		return 0, nil, 0, false, false
	}
	ts, found := bytesField(proc, 8)
	if !found {
		return 0, nil, 0, false, false
	}
	var sec, nanos uint64
	for len(ts) > 0 {
		num, typ, n := protowire.ConsumeTag(ts)
		if n < 0 {
			return 0, nil, 0, false, false
		}
		ts = ts[n:]
		if typ == protowire.VarintType && (num == 1 || num == 2) {
			v, m := protowire.ConsumeVarint(ts)
			if m < 0 {
				return 0, nil, 0, false, false
			}
			if num == 1 {
				sec = v
			} else {
				nanos = v
			}
			ts = ts[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, ts)
		if m < 0 {
			return 0, nil, 0, false, false
		}
		ts = ts[m:]
	}
	if sec > 1<<40 || nanos >= 1e9 {
		return 0, nil, 0, false, false
	}
	return event, execID, int64(sec)*1e9 + int64(nanos), distinct, true //nolint:gosec // G115: bounded above
}

// bytesField returns the last occurrence of length-delimited field num in
// msg (proto3's last-one-wins for a singular field).
func bytesField(msg []byte, num protowire.Number) ([]byte, bool) {
	var out []byte
	found := false
	for len(msg) > 0 {
		n2, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return nil, false
		}
		msg = msg[n:]
		if n2 == num && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(msg)
			if m < 0 {
				return nil, false
			}
			out, found = v, true
			msg = msg[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(n2, typ, msg)
		if m < 0 {
			return nil, false
		}
		msg = msg[m:]
	}
	return out, found
}

package telemetry

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
)

// Auditor records telemetry's security-relevant events. cmd/relayd adapts
// it to the agent's audit sink.
type Auditor interface {
	Record(step, detail string, err error)
}

// SpoolConfig is OpenSpool's input. Every field is required unless noted.
type SpoolConfig struct {
	// Dir is the spool directory (/var/spool/tetragon-relay).
	Dir string
	// FS is the filesystem (OSFS in production).
	FS FS
	// Key is the spool HMAC key: DeriveSpoolKey of the store key.
	Key []byte
	// MaxBytes is collector.spool_max_bytes.
	MaxBytes int64
	// HostUUID, BootID and AgentVersion go into every header. BootID ""
	// means no trustworthy boot ID: never continue a chain.
	HostUUID, BootID, AgentVersion string
	// Tampered is tampered mode (ADR 0038): never continue a chain.
	Tampered bool
	// Epochs returns the current epochs for each header.
	Epochs func() map[string]uint64
	// Clock stamps control batches.
	Clock func() time.Time
	// Rand generates chain IDs.
	Rand io.Reader
	// Auditor records corrupt, orphaned and dropped batches.
	Auditor Auditor
}

// DeriveSpoolKey derives the spool HMAC key from the store key (HKDF with
// SHA-384, ADR 0039 section 5), so internal/telemetry never holds the
// store key itself.
func DeriveSpoolKey(storeKey []byte) ([]byte, error) {
	if len(storeKey) < 32 {
		return nil, fmt.Errorf("telemetry: store key is %d bytes, want >= 32", len(storeKey))
	}
	return hkdfSHA384(storeKey, "tetragon-relay telemetry spool v1", 48)
}

// Entry is one spooled batch.
type Entry struct {
	Gen   uint64
	Chain batch.ChainID
	Seq   uint64
	Hash  batch.Hash
	Class string
	Size  int64
	name  string
}

func (e Entry) before(o Entry) bool {
	if e.Gen != o.Gen {
		return e.Gen < o.Gen
	}
	return e.Seq < o.Seq
}

// Stats is what the heartbeat reports (architecture doc 10.3).
type Stats struct {
	// LastSeq is the highest seq spooled in the current chain.
	LastSeq uint64
	// Backlog is the number of spooled, unacknowledged batches.
	Backlog int
	// Bytes is the spool's size.
	Bytes int64
	// Counters.
	CorruptDropped  uint64
	OverflowDropped uint64
	OrphansRemoved  uint64
	WriteFailures   uint64
}

// Errors.
var (
	// ErrSpoolCorrupt: a batch file failed its integrity check.
	ErrSpoolCorrupt = errors.New("telemetry: spooled batch failed its integrity check")
	// ErrSpoolFull: the spool has no droppable batch left to make room.
	ErrSpoolFull = errors.New("telemetry: spool full of control batches")
)

const (
	fileMagic  = "TRS1"
	headName   = "head"
	fileSuffix = ".batch"
	macSize    = sha512.Size384
)

// Spool is the on-disk spool and the chain head (ADR 0039 sections 3 and
// 5). All methods are safe for concurrent use.
type Spool struct {
	cfg SpoolConfig

	mu     sync.Mutex
	gen    uint64
	chain  batch.ChainID
	seq    uint64
	prev   batch.Hash
	files  []Entry
	total  int64
	stats  Stats
	notify chan struct{}
}

func (c *SpoolConfig) validate() error {
	switch {
	case c.Dir == "" || c.FS == nil:
		return fmt.Errorf("telemetry: spool Dir and FS are required")
	case len(c.Key) < 32:
		return fmt.Errorf("telemetry: spool key must be >= 32 bytes")
	case c.MaxBytes <= 0:
		return fmt.Errorf("telemetry: spool MaxBytes must be positive")
	case c.HostUUID == "" || c.AgentVersion == "":
		return fmt.Errorf("telemetry: spool HostUUID and AgentVersion are required")
	case c.Epochs == nil || c.Clock == nil || c.Rand == nil || c.Auditor == nil:
		return fmt.Errorf("telemetry: spool Epochs, Clock, Rand and Auditor are required")
	}
	return nil
}

// headRecord is the persisted chain head.
type headRecord struct {
	Gen      uint64 `json:"gen"`
	HostUUID string `json:"host_uuid"`
	BootID   string `json:"boot_id"`
	ChainID  string `json:"chain_id"`
	Seq      uint64 `json:"seq"`
	Hash     string `json:"hash"`
}

func (h headRecord) canonical() []byte {
	var b bytes.Buffer
	b.WriteString(`{"gen":` + strconv.FormatUint(h.Gen, 10))
	b.WriteString(`,"host_uuid":` + strconv.Quote(h.HostUUID))
	b.WriteString(`,"boot_id":` + strconv.Quote(h.BootID))
	b.WriteString(`,"chain_id":"` + h.ChainID + `"`)
	b.WriteString(`,"seq":` + strconv.FormatUint(h.Seq, 10))
	b.WriteString(`,"hash":"` + h.Hash + `"}`)
	return b.Bytes()
}

func (s *Spool) mac(parts ...[]byte) []byte {
	m := hmac.New(sha512.New384, s.cfg.Key)
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p))) //nolint:gosec // G115: bounded inputs
		m.Write(n[:])
		m.Write(p)
	}
	return m.Sum(nil)
}

func fileName(gen uint64, chain batch.ChainID, seq uint64) string {
	return fmt.Sprintf("%010d-%s-%020d%s", gen, chain, seq, fileSuffix)
}

func parseFileName(name string) (gen uint64, chain batch.ChainID, seq uint64, ok bool) {
	if !strings.HasSuffix(name, fileSuffix) {
		return 0, chain, 0, false
	}
	parts := strings.Split(strings.TrimSuffix(name, fileSuffix), "-")
	if len(parts) != 3 || len(parts[0]) != 10 || len(parts[1]) != 32 || len(parts[2]) != 20 {
		return 0, chain, 0, false
	}
	g, err1 := strconv.ParseUint(parts[0], 10, 64)
	q, err2 := strconv.ParseUint(parts[2], 10, 64)
	c, err3 := hex.DecodeString(parts[1])
	if err1 != nil || err2 != nil || err3 != nil || q == 0 || hex.EncodeToString(c) != parts[1] {
		return 0, chain, 0, false
	}
	copy(chain[:], c)
	return g, chain, q, true
}

// seal is a batch file's bytes: magic, be32 header length, header,
// payload, and an HMAC-SHA-384 over the file name and all of that.
func (s *Spool) seal(name string, header, payload []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(header))) //nolint:gosec // G115: bounded by MaxTelemetryHeaderBytes
	body := make([]byte, 0, len(fileMagic)+4+len(header)+len(payload)+macSize)
	body = append(body, fileMagic...)
	body = append(body, n[:]...)
	body = append(body, header...)
	body = append(body, payload...)
	return append(body, s.mac([]byte(name), body)...)
}

// unseal checks a batch file and returns its header and payload.
func (s *Spool) unseal(name string, raw []byte) (batch.Batch, error) {
	if len(raw) < len(fileMagic)+4+macSize || string(raw[:len(fileMagic)]) != fileMagic {
		return batch.Batch{}, fmt.Errorf("%w: %s: short or bad magic", ErrSpoolCorrupt, name)
	}
	body, tag := raw[:len(raw)-macSize], raw[len(raw)-macSize:]
	if !hmac.Equal(tag, s.mac([]byte(name), body)) {
		return batch.Batch{}, fmt.Errorf("%w: %s: HMAC mismatch", ErrSpoolCorrupt, name)
	}
	hl := binary.BigEndian.Uint32(body[len(fileMagic):])
	rest := body[len(fileMagic)+4:]
	if uint64(hl) > uint64(len(rest)) {
		return batch.Batch{}, fmt.Errorf("%w: %s: header length", ErrSpoolCorrupt, name)
	}
	b, err := batch.Parse(rest[:hl], rest[hl:])
	if err != nil {
		return batch.Batch{}, fmt.Errorf("%w: %s: %w", ErrSpoolCorrupt, name, err)
	}
	gen, chain, seq, ok := parseFileName(name)
	if !ok || chain != b.Header.ChainID || seq != b.Header.Seq || gen == 0 {
		return batch.Batch{}, fmt.Errorf("%w: %s: name does not match header", ErrSpoolCorrupt, name)
	}
	return b, nil
}

type headState int

const (
	headOK headState = iota
	headMissing
	headCorrupt
)

func (s *Spool) readHead() (headRecord, headState, error) {
	raw, err := s.cfg.FS.ReadFile(filepath.Join(s.cfg.Dir, headName))
	if errors.Is(err, fs.ErrNotExist) {
		return headRecord{}, headMissing, nil
	}
	if err != nil {
		return headRecord{}, headCorrupt, err
	}
	js, tagHex, ok := bytes.Cut(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if !ok {
		return headRecord{}, headCorrupt, errors.New("head: no HMAC line")
	}
	tag, err := hex.DecodeString(string(tagHex))
	if err != nil || !hmac.Equal(tag, s.mac([]byte(headName), js)) {
		return headRecord{}, headCorrupt, errors.New("head: HMAC mismatch")
	}
	var h headRecord
	if err := strictjson.DecodeStrict(js, 2, &h); err != nil {
		return headRecord{}, headCorrupt, fmt.Errorf("head: %w", err)
	}
	var c batch.ChainID
	var hh batch.Hash
	if !bytes.Equal(h.canonical(), js) || h.Gen == 0 || h.Seq == 0 || len(h.ChainID) != 32 || len(h.Hash) != 64 {
		return headRecord{}, headCorrupt, errors.New("head: not canonical")
	}
	if _, err := hex.Decode(c[:], []byte(h.ChainID)); err != nil {
		return headRecord{}, headCorrupt, errors.New("head: chain_id")
	}
	if _, err := hex.Decode(hh[:], []byte(h.Hash)); err != nil {
		return headRecord{}, headCorrupt, errors.New("head: hash")
	}
	return h, headOK, nil
}

func (s *Spool) writeHead(gen uint64, chain batch.ChainID, seq uint64, hash batch.Hash) error {
	js := headRecord{Gen: gen, HostUUID: s.cfg.HostUUID, BootID: s.cfg.BootID, ChainID: chain.String(), Seq: seq, Hash: hash.String()}.canonical()
	out := append(append(append([]byte{}, js...), '\n'), hex.EncodeToString(s.mac([]byte(headName), js))...)
	return writeAtomic(s.cfg.FS, s.cfg.Dir, headName, append(out, '\n'))
}

// OpenSpool loads the spool: it removes temp files, drops (and audits)
// batch files that fail their integrity check and files above the
// persisted head (written but never spooled), then either continues the
// chain from the head or starts a new one with a chain_reset batch.
func OpenSpool(cfg SpoolConfig) (*Spool, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Spool{cfg: cfg, notify: make(chan struct{}, 1)}
	des, err := cfg.FS.ReadDir(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("telemetry: read spool dir: %w", err)
	}
	head, hs, herr := s.readHead()
	var maxGen uint64
	for _, de := range des {
		name := de.Name()
		if strings.HasSuffix(name, tmpSuffix) {
			s.removeQuiet(name)
			continue
		}
		if !strings.HasSuffix(name, fileSuffix) {
			continue
		}
		raw, rerr := cfg.FS.ReadFile(filepath.Join(cfg.Dir, name))
		var b batch.Batch
		if rerr == nil {
			b, rerr = s.unseal(name, raw)
		}
		if rerr != nil {
			s.stats.CorruptDropped++
			cfg.Auditor.Record("telemetry_batch_corrupt", "spooled batch failed its integrity check; deleted, never sent: "+name, rerr)
			s.removeQuiet(name)
			continue
		}
		gen, _, _, _ := parseFileName(name)
		if gen > maxGen {
			maxGen = gen
		}
		s.files = append(s.files, Entry{Gen: gen, Chain: b.Header.ChainID, Seq: b.Header.Seq, Hash: b.Hash, Class: b.Header.Class, Size: int64(len(raw)), name: name})
	}
	if hs == headOK {
		// Files above the head were written but never counted as
		// spooled (a crash between the batch file and the head).
		kept := s.files[:0]
		for _, e := range s.files {
			if e.Gen > head.Gen || (e.Gen == head.Gen && (e.Chain.String() != head.ChainID || e.Seq > head.Seq)) {
				s.stats.OrphansRemoved++
				cfg.Auditor.Record("telemetry_batch_orphan", "batch file above the persisted head was never spooled; deleted, never sent: "+e.name, nil)
				s.removeQuiet(e.name)
				continue
			}
			kept = append(kept, e)
		}
		s.files = kept
		if head.Gen > maxGen {
			maxGen = head.Gen
		}
	}
	if len(des) > 0 {
		_ = cfg.FS.FsyncDir(cfg.Dir)
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].before(s.files[j]) })
	for _, e := range s.files {
		s.total += e.Size
	}

	reason := ""
	var prev *batch.Ref
	switch {
	case cfg.Tampered:
		reason = batch.ReasonTamperedMode
	case cfg.BootID == "":
		reason = batch.ReasonBootIDUnknown
	case hs == headMissing:
		reason = batch.ReasonHeadMissing
	case hs == headCorrupt || head.HostUUID != cfg.HostUUID:
		reason = batch.ReasonHeadCorrupt
		if herr == nil {
			herr = errors.New("head names another host")
		}
	case head.BootID != cfg.BootID:
		reason = batch.ReasonBootChanged
	}
	if hs == headOK && (reason == batch.ReasonBootChanged || reason == batch.ReasonTamperedMode || reason == batch.ReasonBootIDUnknown) && head.HostUUID == cfg.HostUUID {
		r := batch.Ref{Seq: head.Seq}
		_, _ = hex.Decode(r.ChainID[:], []byte(head.ChainID))
		_, _ = hex.Decode(r.Hash[:], []byte(head.Hash))
		prev = &r
	}
	if hs == headCorrupt || (hs == headOK && head.HostUUID != cfg.HostUUID) {
		cfg.Auditor.Record("telemetry_head_corrupt", "chain head cannot be trusted; starting a new chain", herr)
	}
	if reason == "" {
		s.gen = head.Gen
		_, _ = hex.Decode(s.chain[:], []byte(head.ChainID))
		_, _ = hex.Decode(s.prev[:], []byte(head.Hash))
		s.seq = head.Seq
		cfg.Auditor.Record("telemetry_chain_continued", fmt.Sprintf("chain %s continues at seq %d", s.chain, s.seq+1), nil)
		return s, nil
	}
	s.gen = maxGen + 1
	if _, err := io.ReadFull(cfg.Rand, s.chain[:]); err != nil {
		return nil, fmt.Errorf("telemetry: chain id: %w", err)
	}
	payload, err := (&batch.Reset{Reason: reason, Prev: prev}).Marshal()
	if err != nil {
		return nil, err
	}
	now := cfg.Clock().UnixNano()
	s.mu.Lock()
	_, err = s.appendLocked(batch.KindChainReset, batch.ClassControl, 0, now, now, payload)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("telemetry: start chain: %w", err)
	}
	cfg.Auditor.Record("telemetry_chain_reset", fmt.Sprintf("new chain %s (reason %s)", s.chain, reason), nil)
	return s, nil
}

func (s *Spool) removeQuiet(name string) {
	_ = s.cfg.FS.Remove(filepath.Join(s.cfg.Dir, name))
}

// appendLocked writes one batch: the batch file first, then the head. It
// counts as spooled only after the head is written.
func (s *Spool) appendLocked(kind, class string, count uint64, first, last int64, payload []byte) (Entry, error) {
	h := batch.Header{
		HostUUID: s.cfg.HostUUID, BootID: s.cfg.BootID, ChainID: s.chain, Seq: s.seq + 1, PrevHash: s.prev,
		Kind: kind, Class: class, Count: count, FirstTS: first, LastTS: last,
		AgentVersion: s.cfg.AgentVersion, Epochs: s.cfg.Epochs(), PayloadSHA256: sha256Sum(payload),
	}
	if h.Epochs == nil {
		h.Epochs = map[string]uint64{}
	}
	raw, err := h.Marshal()
	if err != nil {
		return Entry{}, err
	}
	hash := batch.HashOf(raw, payload)
	name := fileName(s.gen, s.chain, h.Seq)
	content := s.seal(name, raw, payload)
	if err := writeAtomic(s.cfg.FS, s.cfg.Dir, name, content); err != nil {
		s.stats.WriteFailures++
		return Entry{}, err
	}
	if err := s.writeHead(s.gen, s.chain, h.Seq, hash); err != nil {
		s.stats.WriteFailures++
		// The file is above the head on disk: OpenSpool removes it.
		s.removeQuiet(name)
		return Entry{}, err
	}
	e := Entry{Gen: s.gen, Chain: s.chain, Seq: h.Seq, Hash: hash, Class: class, Size: int64(len(content)), name: name}
	s.seq, s.prev = h.Seq, hash
	s.files = append(s.files, e)
	s.total += e.Size
	s.signal()
	return e, nil
}

func (s *Spool) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// AppendEvents spools one events batch of class. If the spool would
// exceed MaxBytes, the oldest non_security batches are dropped first, then
// the oldest security batches; a dropped record listing them is written
// before they are deleted, so the loss is in the chain even across a
// crash.
func (s *Spool) AppendEvents(class string, records [][]byte, first, last int64) (Entry, error) {
	if class != batch.ClassSecurity && class != batch.ClassNonSecurity {
		return Entry{}, fmt.Errorf("telemetry: AppendEvents class %q", class)
	}
	var payload []byte
	for _, r := range records {
		payload = batch.AppendRecord(payload, r)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	need := int64(len(payload)) + int64(len(fileMagic)+4+macSize+limits.MaxTelemetryHeaderBytes/4)
	if err := s.makeRoomLocked(need); err != nil {
		return Entry{}, err
	}
	return s.appendLocked(batch.KindEvents, class, uint64(len(records)), first, last, payload)
}

func (s *Spool) makeRoomLocked(need int64) error {
	if s.total+need <= s.cfg.MaxBytes {
		return nil
	}
	victims := map[string][]Entry{}
	var freed int64
	for _, class := range []string{batch.ClassNonSecurity, batch.ClassSecurity} {
		for _, e := range s.files {
			if s.total-freed+need <= s.cfg.MaxBytes {
				break
			}
			if e.Class == class {
				victims[class] = append(victims[class], e)
				freed += e.Size
			}
		}
	}
	if s.total-freed+need > s.cfg.MaxBytes && len(victims) == 0 {
		s.stats.WriteFailures++
		s.cfg.Auditor.Record("telemetry_spool_full", "spool holds only control batches; new events batch not spooled", ErrSpoolFull)
		return ErrSpoolFull
	}
	now := s.cfg.Clock().UnixNano()
	for _, class := range []string{batch.ClassNonSecurity, batch.ClassSecurity} {
		vs := victims[class]
		for len(vs) > 0 {
			n := min(len(vs), limits.MaxDroppedEntriesPerRecord)
			d := batch.Dropped{Class: class}
			for _, e := range vs[:n] {
				d.Batches = append(d.Batches, batch.Ref{ChainID: e.Chain, Seq: e.Seq, Hash: e.Hash})
			}
			p, err := d.Marshal()
			if err != nil {
				return err
			}
			// The dropped record is durable before anything is deleted.
			if _, err := s.appendLocked(batch.KindDropped, batch.ClassControl, 0, now, now, p); err != nil {
				return err
			}
			for _, e := range vs[:n] {
				s.removeEntryLocked(e.name)
			}
			_ = s.cfg.FS.FsyncDir(s.cfg.Dir)
			s.stats.OverflowDropped += uint64(n) //nolint:gosec // G115: n is bounded
			s.cfg.Auditor.Record("telemetry_batches_dropped", fmt.Sprintf("spool over %d bytes: dropped %d %s batch(es), declared in seq %d", s.cfg.MaxBytes, n, class, s.seq), nil)
			vs = vs[n:]
		}
	}
	return nil
}

func (s *Spool) removeEntryLocked(name string) {
	for i, e := range s.files {
		if e.name == name {
			s.removeQuiet(name)
			s.total -= e.Size
			s.files = append(s.files[:i], s.files[i+1:]...)
			return
		}
	}
}

// Ack deletes every spooled batch of chain with seq <= seq and returns how
// many it deleted. The exporter validates the ack before calling this.
func (s *Spool) Ack(chain batch.ChainID, seq uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	kept := s.files[:0]
	for _, e := range s.files {
		if e.Chain == chain && e.Seq <= seq {
			s.removeQuiet(e.name)
			s.total -= e.Size
			n++
			continue
		}
		kept = append(kept, e)
	}
	s.files = kept
	if n > 0 {
		_ = s.cfg.FS.FsyncDir(s.cfg.Dir)
	}
	return n
}

// After returns the oldest spooled entry after cur (or the oldest of all
// when cur is nil).
func (s *Spool) After(cur *Entry) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.files {
		if cur == nil || cur.before(e) {
			return e, true
		}
	}
	return Entry{}, false
}

// Read returns e's header and payload after checking its integrity. A
// file that fails the check is deleted, counted and audited, and
// ErrSpoolCorrupt is returned: it is never sent. A file deleted since it
// was listed (acked or dropped) returns fs.ErrNotExist.
func (s *Spool) Read(e Entry) (header, payload []byte, err error) {
	raw, err := s.cfg.FS.ReadFile(filepath.Join(s.cfg.Dir, e.name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
	}
	var b batch.Batch
	if err == nil {
		b, err = s.unseal(e.name, raw)
		if err == nil && b.Hash != e.Hash {
			err = fmt.Errorf("%w: %s: hash changed since it was spooled", ErrSpoolCorrupt, e.name)
		}
	}
	if err != nil {
		s.mu.Lock()
		s.stats.CorruptDropped++
		s.removeEntryLocked(e.name)
		s.mu.Unlock()
		s.cfg.Auditor.Record("telemetry_batch_corrupt", "spooled batch failed its integrity check on read; deleted, never sent: "+e.name, err)
		return nil, nil, fmt.Errorf("%w: %w", ErrSpoolCorrupt, err)
	}
	return b.RawHeader, b.Payload, nil
}

// Notify receives a value after every append.
func (s *Spool) Notify() <-chan struct{} { return s.notify }

// Stats returns the current counters.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.LastSeq = s.seq
	st.Backlog = len(s.files)
	st.Bytes = s.total
	return st
}

// Chain returns the current chain's ID.
func (s *Spool) Chain() batch.ChainID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain
}

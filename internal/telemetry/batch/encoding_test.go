package batch

import (
	"bytes"
	"errors"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func zstdHeader() *Header {
	h := sampleHeader()
	return &h
}

func TestPayloadCodec_RoundTripAndNone(t *testing.T) {
	enc, err := NewPayloadEncoder()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewPayloadDecoder()
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	raw := bytes.Repeat(AppendRecord(nil, []byte("a realistic-ish event record")), 1000)
	z := enc.Encode(raw)
	if len(z) >= len(raw)/4 {
		t.Fatalf("compressed %d -> %d", len(raw), len(z))
	}
	got, err := dec.Decode(zstdHeader(), z)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("round trip: %v", err)
	}
	v1 := v1Sample()
	if got, err := dec.Decode(&v1, []byte("plain")); err != nil || string(got) != "plain" {
		t.Fatalf("v1 payload: %q %v", got, err)
	}
	h := sampleHeader()
	h.Enc = EncNone
	if got, err := dec.Decode(&h, []byte("plain")); err != nil || string(got) != "plain" {
		t.Fatalf("enc none: %q %v", got, err)
	}
	h.Enc = "gzip"
	if _, err := dec.Decode(&h, []byte("x")); !errors.Is(err, ErrBadPayload) {
		t.Fatalf("unknown enc: %v", err)
	}
}

// Decompression bombs: a payload that decodes past the limit is rejected
// however it is framed (one frame that declares its size, a streamed frame
// that does not, many frames), and exactly the limit is accepted.
func TestPayloadDecoder_Limit(t *testing.T) {
	dec, _ := NewPayloadDecoder()
	defer dec.Close()
	lim := limits.MaxTelemetryDecodedPayloadBytes
	oneFrame := func(n int) []byte {
		e, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		return e.EncodeAll(make([]byte, n), nil)
	}
	streamed := func(n int) []byte {
		var buf bytes.Buffer
		e, _ := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
		_, _ = e.Write(make([]byte, n))
		_ = e.Close()
		return buf.Bytes()
	}
	if got, err := dec.Decode(zstdHeader(), oneFrame(lim)); err != nil || len(got) != lim {
		t.Fatalf("exactly the limit: %d %v", len(got), err)
	}
	bombs := map[string][]byte{
		"one frame, limit+1":        oneFrame(lim + 1),
		"one frame, 64 MiB":         oneFrame(64 << 20),
		"streamed, no size, +1":     streamed(lim + 1),
		"streamed, no size, 1 GiB":  streamed(1 << 30),
		"two frames over the limit": append(oneFrame(lim/2+1), oneFrame(lim/2+1)...),
		"many small frames":         bytes.Repeat(oneFrame(1<<20), 9),
	}
	for name, z := range bombs {
		if len(z) > limits.MaxTelemetryPayloadBytes {
			t.Fatalf("%s: bomb is %d bytes compressed; it should fit a payload", name, len(z))
		}
		_, err := dec.Decode(zstdHeader(), z)
		if !errors.Is(err, ErrBadPayload) || !errors.Is(err, ErrDecodedTooLarge) {
			t.Errorf("%s (%d bytes compressed): err = %v, want ErrDecodedTooLarge", name, len(z), err)
		}
	}
	for name, z := range map[string][]byte{"garbage": []byte("not zstd at all"), "empty": nil, "truncated": oneFrame(1000)[:10]} {
		if _, err := dec.Decode(zstdHeader(), z); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The decoder still works after rejecting bombs.
	if got, err := dec.Decode(zstdHeader(), oneFrame(10)); err != nil || len(got) != 10 {
		t.Fatalf("after bombs: %d %v", len(got), err)
	}
}

func FuzzPayloadDecode(f *testing.F) {
	e, _ := zstd.NewWriter(nil)
	f.Add(e.EncodeAll([]byte("hello hello hello"), nil))
	f.Add(e.EncodeAll(make([]byte, 1<<16), nil))
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd})
	dec, err := NewPayloadDecoder()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, z []byte) {
		out, err := dec.Decode(zstdHeader(), z)
		if err == nil && (len(out) == 0 || len(out) > limits.MaxTelemetryDecodedPayloadBytes) {
			t.Fatalf("decoded %d bytes", len(out))
		}
		if err != nil && !errors.Is(err, ErrBadPayload) {
			t.Fatalf("untyped error %v", err)
		}
	})
}

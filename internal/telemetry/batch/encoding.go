package batch

import (
	"errors"
	"fmt"

	"github.com/klauspost/compress/zstd"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// ErrDecodedTooLarge means a compressed payload decodes to more than
// limits.MaxTelemetryDecodedPayloadBytes (a decompression bomb, or not a
// payload this agent produced).
var ErrDecodedTooLarge = errors.New("batch: compressed payload exceeds the decoded size limit")

// PayloadDecoder decodes payloads by their header's enc, never producing
// more than limits.MaxTelemetryDecodedPayloadBytes: the zstd decoder's
// in-memory limit (WithDecoderMaxMemory, also bounding the window), and
// DecodeAll into a buffer whose capacity is that limit with
// WithDecodeAllCapLimit, so even a frame that does not declare its size
// stops at the limit instead of growing the output. One decoder is not
// safe for concurrent use; the slice Decode returns is valid until the
// next call.
type PayloadDecoder struct {
	zd  *zstd.Decoder
	buf []byte
}

// NewPayloadDecoder returns a decoder.
func NewPayloadDecoder() (*PayloadDecoder, error) {
	zd, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(limits.MaxTelemetryDecodedPayloadBytes),
		zstd.WithDecoderMaxWindow(limits.MaxTelemetryDecodedPayloadBytes),
		zstd.WithDecodeAllCapLimit(true),
	)
	if err != nil {
		return nil, fmt.Errorf("batch: zstd decoder: %w", err)
	}
	return &PayloadDecoder{zd: zd}, nil
}

// Decode returns payload decoded per h.Encoding(): payload itself for
// EncNone, the decompressed bytes for EncZstd. Errors wrap ErrBadPayload
// (and ErrDecodedTooLarge for an oversized result).
func (d *PayloadDecoder) Decode(h *Header, payload []byte) ([]byte, error) {
	switch h.Encoding() {
	case EncNone:
		return payload, nil
	case EncZstd:
	default:
		return nil, fmt.Errorf("%w: enc %q", ErrBadPayload, h.Encoding())
	}
	if cap(d.buf) < limits.MaxTelemetryDecodedPayloadBytes {
		d.buf = make([]byte, 0, limits.MaxTelemetryDecodedPayloadBytes)
	}
	out, err := d.zd.DecodeAll(payload, d.buf[:0])
	switch {
	case errors.Is(err, zstd.ErrDecoderSizeExceeded), errors.Is(err, zstd.ErrWindowSizeExceeded):
		return nil, fmt.Errorf("%w: %w: %w", ErrBadPayload, ErrDecodedTooLarge, err)
	case err != nil:
		return nil, fmt.Errorf("%w: zstd: %w", ErrBadPayload, err)
	case len(out) > limits.MaxTelemetryDecodedPayloadBytes:
		return nil, fmt.Errorf("%w: %w", ErrBadPayload, ErrDecodedTooLarge)
	case len(out) == 0:
		return nil, fmt.Errorf("%w: zstd payload decodes to nothing", ErrBadPayload)
	}
	return out, nil
}

// Close releases the decoder.
func (d *PayloadDecoder) Close() { d.zd.Close() }

// PayloadEncoder compresses events payloads (enc "zstd") at
// zstd.SpeedFastest. One encoder is not safe for concurrent use; the
// slice Encode returns is valid until the next call.
type PayloadEncoder struct {
	ze  *zstd.Encoder
	buf []byte
}

// NewPayloadEncoder returns an encoder.
func NewPayloadEncoder() (*PayloadEncoder, error) {
	ze, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return nil, fmt.Errorf("batch: zstd encoder: %w", err)
	}
	return &PayloadEncoder{ze: ze}, nil
}

// Encode returns raw compressed as one zstd frame (with its content size
// and a checksum).
func (e *PayloadEncoder) Encode(raw []byte) []byte {
	e.buf = e.ze.EncodeAll(raw, e.buf[:0])
	return e.buf
}

package dsse

import (
	"encoding/base64"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// wireEnvelope mirrors the JSON shape in architecture doc section 7.3
// exactly: {"payloadType", "payload", "signatures":[{"keyid","sig"}]}.
type wireEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []wireSignature `json:"signatures"`
}

type wireSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Envelope is a parsed, base64-decoded DSSE envelope. PayloadType and
// Payload are exactly the bytes that were (or claim to have been) signed;
// nothing here has been cryptographically verified yet.
type Envelope struct {
	PayloadType string
	Payload     []byte
	Signatures  []Signature
}

// Signature is one decoded {keyid, sig} pair from an envelope.
type Signature struct {
	KeyID string
	Sig   []byte
}

// decodeBase64Strict requires standard, canonically padded base64 (RFC 4648
// §4), rejecting non-canonical encodings that some decoders tolerate.
func decodeBase64Strict(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBase64, err)
	}
	return b, nil
}

// ParseEnvelope parses and base64-decodes a DSSE envelope. It enforces:
//   - maxBytes on the raw input, checked before any parsing
//   - strict JSON (internal/strictjson): no unknown fields, no duplicate
//     keys, bounded nesting depth, valid UTF-8, no trailing data
//   - strict, canonical base64 for the payload and every signature
//
// It does not verify any signature; that requires a public key and is the
// caller's (internal/trust's) responsibility.
func ParseEnvelope(data []byte, maxBytes, maxDepth int) (*Envelope, error) {
	if len(data) > maxBytes {
		return nil, ErrEnvelopeTooLarge
	}

	var w wireEnvelope
	if err := strictjson.DecodeStrict(data, maxDepth, &w); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	if w.PayloadType == "" || w.Payload == "" {
		return nil, fmt.Errorf("%w: missing payloadType or payload", ErrInvalidEnvelope)
	}
	if len(w.Signatures) == 0 {
		return nil, ErrNoSignatures
	}

	payload, err := decodeBase64Strict(w.Payload)
	if err != nil {
		return nil, err
	}

	sigs := make([]Signature, 0, len(w.Signatures))
	for _, ws := range w.Signatures {
		if ws.KeyID == "" {
			return nil, fmt.Errorf("%w: signature missing keyid", ErrInvalidEnvelope)
		}
		sigBytes, err := decodeBase64Strict(ws.Sig)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, Signature{KeyID: ws.KeyID, Sig: sigBytes})
	}

	return &Envelope{
		PayloadType: w.PayloadType,
		Payload:     payload,
		Signatures:  sigs,
	}, nil
}

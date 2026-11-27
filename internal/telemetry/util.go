package telemetry

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
)

func sha256Sum(b []byte) batch.Hash { return sha256.Sum256(b) }

func hkdfSHA384(secret []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(sha512.New384, secret, nil, info, n)
}

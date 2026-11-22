//go:build testtools

package main

import (
	"encoding/base64"
	"encoding/json"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
)

// wireSignature and wireEnvelope mirror the DSSE JSON shape parsed by
// internal/dsse.ParseEnvelope (architecture doc section 7.3) exactly.
type wireSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type wireEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []wireSignature `json:"signatures"`
}

// signEnvelope builds and signs a DSSE envelope for payload under
// payloadType, with one signature per signer, in order. The PAE
// construction is reused from internal/dsse so the generator and the
// verifier can never disagree about what bytes are signed.
func signEnvelope(payloadType string, payload []byte, signers ...*testKey) ([]byte, error) {
	pae := dsse.PAE(payloadType, payload)

	sigs := make([]wireSignature, 0, len(signers))
	for _, k := range signers {
		sigDER, err := k.sign(pae)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, wireSignature{KeyID: k.id, Sig: base64.StdEncoding.EncodeToString(sigDER)})
	}

	env := wireEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  sigs,
	}
	return json.Marshal(env)
}

// rawEnvelopeWithSigs re-marshals an envelope's payload with an explicit,
// caller-provided signature list, bypassing signEnvelope's "sign everything"
// convenience. Used to build vectors such as "duplicate signature, same
// key" or "signature from a key not in the target role" where the caller
// needs precise control over which signatures appear.
func rawEnvelopeWithSigs(payloadType string, payload []byte, sigs []wireSignature) ([]byte, error) {
	env := wireEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  sigs,
	}
	return json.Marshal(env)
}

func makeSig(k *testKey, pae []byte) (wireSignature, error) {
	sigDER, err := k.sign(pae)
	if err != nil {
		return wireSignature{}, err
	}
	return wireSignature{KeyID: k.id, Sig: base64.StdEncoding.EncodeToString(sigDER)}, nil
}

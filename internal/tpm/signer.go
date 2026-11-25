package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// hostSignerSchema identifies the on-disk host-signing-key blob format.
const hostSignerSchema = "relay.tpm.host_signer.v1"

// hostSignerBlobFile is the on-disk schema for a host signing key: a
// TPM2B_PUBLIC/TPM2B_PRIVATE pair (not secret -- the private area is
// encrypted to the SRK) plus the curve name recorded for host-facts
// reporting (docs/prompts/step-05a.md C4: "record it in host facts")
// without needing to re-parse the public area just to know which curve
// was used.
type hostSignerBlobFile struct {
	Schema  string `json:"schema"`
	Curve   string `json:"curve"` // "P-384" or "P-256"
	Public  string `json:"public_b64"`
	Private string `json:"private_b64"`
}

// CurveP384 and CurveP256 are the two curve names HostSigner reports in
// host facts (docs/prompts/step-05a.md C4). This project never falls back
// to any other curve or to a software key.
const (
	CurveP384 = "P-384"
	CurveP256 = "P-256"
)

// HostSigner is a crypto.Signer backed by a non-exportable TPM signing
// key: fixedTPM, fixedParent, sensitiveDataOrigin, sign-only (no
// decrypt), ECC P-384 if the TPM supports it, else P-256
// (docs/decisions/0028-host-signing-key-curve-fallback.md). The private
// key handle never leaves the TPM; HostSigner re-loads the sealed
// public/private blob under a freshly created SRK on every Sign call,
// the same "no cached TPM session/handle across calls" discipline
// KeySealer uses.
type HostSigner struct {
	t         transport.TPM
	blobPath  string
	curve     string
	pub       *ecdsa.PublicKey
	pubBytes  []byte // raw marshaled TPMT_PUBLIC, for Load
	privBytes []byte
}

// detectSigningCurve runs TPM2_TestParms for ECC P-384 and, if
// unavailable, ECC P-256, both with an ECDSA scheme using that curve's
// natural hash (SHA-384 for P-384, SHA-256 for P-256). It never falls
// back further than that (docs/prompts/step-05a.md C4: "Never fall back
// to a software key").
func detectSigningCurve(t transport.TPM) (string, error) {
	if testECCParms(t, tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384) {
		return CurveP384, nil
	}
	if testECCParms(t, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256) {
		return CurveP256, nil
	}
	return "", ErrNoSupportedSigningCurve
}

func testECCParms(t transport.TPM, curve tpm2.TPMECCCurve, hashAlg tpm2.TPMAlgID) bool {
	cmd := tpm2.TestParms{
		Parameters: tpm2.TPMTPublicParms{
			Type: tpm2.TPMAlgECC,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: hashAlg}),
				},
				CurveID: curve,
			}),
		},
	}
	_, err := cmd.Execute(t)
	return err == nil
}

// eccPointToPublicKey builds an *ecdsa.PublicKey from raw, big-endian X/Y
// coordinate buffers (as the TPM returns them) via the SEC1 uncompressed
// point encoding (0x04 || X || Y, each left-padded to coordSize) and
// ecdsa.ParseUncompressedPublicKey, rather than constructing an
// ecdsa.PublicKey's deprecated X/Y fields directly (crypto/ecdsa: "To
// encode and decode PublicKey values, use PublicKey.Bytes and
// ParseUncompressedPublicKey", deprecated since Go 1.26).
func eccPointToPublicKey(curve elliptic.Curve, coordSize int, xBuf, yBuf []byte) (*ecdsa.PublicKey, error) {
	point := make([]byte, 1+2*coordSize)
	point[0] = 0x04
	copy(point[1+coordSize-len(xBuf):1+coordSize], xBuf)
	copy(point[1+2*coordSize-len(yBuf):1+2*coordSize], yBuf)
	return ecdsa.ParseUncompressedPublicKey(curve, point)
}

func curveParams(curve string) (eccCurve tpm2.TPMECCCurve, nameAlg, hashAlg tpm2.TPMAlgID, goCurve elliptic.Curve, coordSize int, err error) {
	switch curve {
	case CurveP384:
		return tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384, tpm2.TPMAlgSHA384, elliptic.P384(), 48, nil
	case CurveP256:
		return tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA256, elliptic.P256(), 32, nil
	default:
		return 0, 0, 0, nil, 0, fmt.Errorf("tpm: unknown curve %q", curve)
	}
}

func signingKeyTemplate(curve string) (tpm2.TPM2BPublic, error) {
	eccCurve, nameAlg, hashAlg, _, coordSize, err := curveParams(curve)
	if err != nil {
		return tpm2.TPM2BPublic{}, err
	}
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: nameAlg,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: hashAlg}),
			},
			CurveID: eccCurve,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, coordSize)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, coordSize)},
		}),
	}), nil
}

// NewOrLoadHostSigner opens the host signing key at blobPath, generating
// one on first boot (blobPath does not exist yet). See HostSigner.
func NewOrLoadHostSigner(t transport.TPM, blobPath string) (*HostSigner, error) {
	if _, err := os.Stat(blobPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("tpm: stat host signer blob %s: %w", blobPath, err)
		}
		if err := createHostSigner(t, blobPath); err != nil {
			return nil, err
		}
	}
	return loadHostSigner(t, blobPath)
}

func createHostSigner(t transport.TPM, blobPath string) error {
	curve, err := detectSigningCurve(t)
	if err != nil {
		return err
	}
	template, err := signingKeyTemplate(curve)
	if err != nil {
		return err
	}
	srkHandle, srkName, err := CreateSRK(t)
	if err != nil {
		return err
	}
	defer func() { _ = FlushSRK(t, srkHandle) }()

	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{}},
		InPublic:     template,
	}
	createRsp, err := create.Execute(t)
	if err != nil {
		return fmt.Errorf("%w: create host signing key: %w", ErrTPMCommand, err)
	}
	blob := hostSignerBlobFile{
		Schema:  hostSignerSchema,
		Curve:   curve,
		Public:  base64.StdEncoding.EncodeToString(createRsp.OutPublic.Bytes()),
		Private: base64.StdEncoding.EncodeToString(createRsp.OutPrivate.Buffer),
	}
	b, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("tpm: marshal host signer blob: %w", err)
	}
	return writeFileAtomic(blobPath, b, 0o600)
}

func loadHostSigner(t transport.TPM, blobPath string) (*HostSigner, error) {
	raw, err := os.ReadFile(blobPath) //nolint:gosec // G304: blobPath is always derived from this package's own caller-supplied store-directory path, never untrusted input
	if err != nil {
		return nil, fmt.Errorf("tpm: read host signer blob %s: %w", blobPath, err)
	}
	var blob hostSignerBlobFile
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("tpm: parse host signer blob: %w", err)
	}
	if blob.Schema != hostSignerSchema {
		return nil, fmt.Errorf("tpm: unexpected host signer blob schema %q", blob.Schema)
	}
	_, _, _, goCurve, coordSize, err := curveParams(blob.Curve)
	if err != nil {
		return nil, err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(blob.Public)
	if err != nil {
		return nil, fmt.Errorf("tpm: decode host signer public: %w", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(blob.Private)
	if err != nil {
		return nil, fmt.Errorf("tpm: decode host signer private: %w", err)
	}
	pub2B := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)
	pubArea, err := pub2B.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: parse host signer public area: %w", err)
	}
	eccPub, err := pubArea.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm: host signer public is not an ECC point: %w", err)
	}
	pub, err := eccPointToPublicKey(goCurve, coordSize, eccPub.X.Buffer, eccPub.Y.Buffer)
	if err != nil {
		return nil, fmt.Errorf("tpm: host signer public point: %w", err)
	}
	return &HostSigner{t: t, blobPath: blobPath, curve: blob.Curve, pub: pub, pubBytes: pubBytes, privBytes: privBytes}, nil
}

// Curve reports which curve this host signer uses ("P-384" or "P-256"),
// for host-facts reporting (docs/prompts/step-05a.md C4).
func (h *HostSigner) Curve() string { return h.curve }

// Public implements crypto.Signer.
func (h *HostSigner) Public() crypto.PublicKey { return h.pub }

// Sign implements crypto.Signer: digest must already be hashed with this
// key's curve's natural hash (SHA-384 for P-384, SHA-256 for P-256),
// matching opts.HashFunc() -- the same precondition every crypto.Signer
// in the standard library (e.g. *ecdsa.PrivateKey) has. The private key
// handle is loaded under a fresh SRK for this one TPM2_Sign call and
// flushed immediately after; it is never cached across calls.
func (h *HostSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_, _, hashAlg, _, coordSize, err := curveParams(h.curve)
	if err != nil {
		return nil, err
	}
	if opts != nil && opts.HashFunc() != 0 && opts.HashFunc().Size() != len(digest) {
		return nil, fmt.Errorf("tpm: digest is %d bytes, want %d for %s", len(digest), opts.HashFunc().Size(), opts.HashFunc())
	}
	if len(digest) != coordSize {
		return nil, fmt.Errorf("tpm: digest is %d bytes, want %d for curve %s", len(digest), coordSize, h.curve)
	}

	srkHandle, srkName, err := CreateSRK(h.t)
	if err != nil {
		return nil, err
	}
	defer func() { _ = FlushSRK(h.t, srkHandle) }()

	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: h.privBytes},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](h.pubBytes),
	}
	loadRsp, err := load.Execute(h.t)
	if err != nil {
		return nil, fmt.Errorf("%w: load host signing key: %w", ErrTPMCommand, err)
	}
	defer func() {
		fc := tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}
		_, _ = fc.Execute(h.t)
	}()

	signCmd := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: hashAlg}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}
	signRsp, err := signCmd.Execute(h.t)
	if err != nil {
		return nil, fmt.Errorf("%w: sign: %w", ErrTPMCommand, err)
	}
	sig, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpm: signature is not ECDSA: %w", err)
	}
	return marshalECDSASignature(sig.SignatureR.Buffer, sig.SignatureS.Buffer)
}

// marshalECDSASignature encodes r, s as the ASN.1 DER SEQUENCE{INTEGER,
// INTEGER} crypto/tls and crypto/x509 expect from any crypto.Signer over
// an ECDSA public key (the same encoding (*ecdsa.PrivateKey).Sign
// produces).
func marshalECDSASignature(rBytes, sBytes []byte) ([]byte, error) {
	type ecdsaSig struct{ R, S *big.Int }
	return asn1.Marshal(ecdsaSig{
		R: new(big.Int).SetBytes(rBytes),
		S: new(big.Int).SetBytes(sBytes),
	})
}

// RotateHostSigner creates a brand-new host signing key (independently
// curve-detected -- a TPM firmware update between rotations could change
// which curve is available) and writes it to newBlobPath, while leaving
// the key at retiredBlobPath (if any already exists there from a PRIOR
// rotation) untouched. The CALLER decides where the currently-active
// blobPath should point after this returns (typically: rename the old
// active blob to retiredBlobPath, write the new key to the old active
// blobPath's name) -- this function only ever creates, never deletes or
// renames, matching docs/prompts/step-05a.md C4's "keep the old one until
// told to retire it."
func RotateHostSigner(t transport.TPM, newBlobPath string) (*HostSigner, error) {
	if err := createHostSigner(t, newBlobPath); err != nil {
		return nil, err
	}
	return loadHostSigner(t, newBlobPath)
}

// RetireHostSigner permanently removes a retired host signing key's blob
// file. This is the explicit "told to retire it" action
// (docs/prompts/step-05a.md C4); nothing in this package calls it on its
// own.
func RetireHostSigner(retiredBlobPath string) error {
	if err := os.Remove(retiredBlobPath); err != nil {
		return fmt.Errorf("tpm: retire host signer blob %s: %w", retiredBlobPath, err)
	}
	return nil
}

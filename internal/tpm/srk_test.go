package tpm

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// persistSRKTemplateAt directly creates and persists a key matching
// SRKTemplate at handle, bypassing ProvisionSRK, so tests can set up "the
// standard handle already has the right object" and similar scenarios
// independently of the function under test.
func persistSRKTemplateAt(t *testing.T, tp transport.TPM, handle tpm2.TPMHandle) {
	t.Helper()
	transientHandle, _, err := CreateSRK(tp)
	if err != nil {
		t.Fatalf("CreateSRK: %v", err)
	}
	defer func() { _ = FlushSRK(tp, transientHandle) }()
	evict := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     tpm2.NamedHandle{Handle: transientHandle},
		PersistentHandle: handle,
	}
	if _, err := evict.Execute(tp); err != nil {
		t.Fatalf("EvictControl at %#x: %v", handle, err)
	}
}

// persistMismatchedObjectAt persists a KEYEDHASH object (not an ECC
// primary at all) at handle, so srkTemplateMatches must reject it.
func persistMismatchedObjectAt(t *testing.T, tp transport.TPM, handle tpm2.TPMHandle) {
	t.Helper()
	srkHandle, srkName, err := CreateSRK(tp)
	if err != nil {
		t.Fatalf("CreateSRK (parent): %v", err)
	}
	defer func() { _ = FlushSRK(tp, srkHandle) }()
	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: []byte("not-an-srk")})},
		},
		InPublic: sealedObjectTemplate(),
	}
	createRsp, err := create.Execute(tp)
	if err != nil {
		t.Fatalf("Create (mismatched object): %v", err)
	}
	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    createRsp.OutPrivate,
		InPublic:     createRsp.OutPublic,
	}
	loadRsp, err := load.Execute(tp)
	if err != nil {
		t.Fatalf("Load (mismatched object): %v", err)
	}
	defer func() {
		fc := tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}
		_, _ = fc.Execute(tp)
	}()
	evict := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     tpm2.NamedHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name},
		PersistentHandle: handle,
	}
	if _, err := evict.Execute(tp); err != nil {
		t.Fatalf("EvictControl (mismatched object) at %#x: %v", handle, err)
	}
}

func TestProvisionSRK_ReusesTCGStandardHandleIfAlreadyCorrect(t *testing.T) {
	tt := startSWTPM(t)
	persistSRKTemplateAt(t, tt, TCGStandardSRKHandle)

	handle, err := ProvisionSRK(tt, nil)
	if err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	if handle != TCGStandardSRKHandle {
		t.Fatalf("ProvisionSRK handle = %#x, want TCGStandardSRKHandle %#x (already correct there, must not touch ProjectSRKHandle)", handle, TCGStandardSRKHandle)
	}
	if _, _, ok, err := readPersistentPublic(tt, ProjectSRKHandle); err != nil {
		t.Fatalf("readPersistentPublic(ProjectSRKHandle): %v", err)
	} else if ok {
		t.Fatalf("ProvisionSRK created an object at ProjectSRKHandle despite TCGStandardSRKHandle already matching")
	}

	gotHandle, gotName, err := OpenSRK(tt)
	if err != nil {
		t.Fatalf("OpenSRK: %v", err)
	}
	if gotHandle != TCGStandardSRKHandle || len(gotName.Buffer) == 0 {
		t.Fatalf("OpenSRK = (%#x, %v), want TCGStandardSRKHandle with a non-empty name", gotHandle, gotName)
	}
}

func TestProvisionSRK_FallsThroughWhenStandardHandleMismatched(t *testing.T) {
	tt := startSWTPM(t)
	persistMismatchedObjectAt(t, tt, TCGStandardSRKHandle)

	handle, err := ProvisionSRK(tt, nil)
	if err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	if handle != ProjectSRKHandle {
		t.Fatalf("ProvisionSRK handle = %#x, want ProjectSRKHandle %#x (standard handle is occupied by a non-matching object)", handle, ProjectSRKHandle)
	}
}

func TestProvisionSRK_RefusesMismatchedProjectHandle(t *testing.T) {
	tt := startSWTPM(t)
	persistMismatchedObjectAt(t, tt, ProjectSRKHandle)

	if _, err := ProvisionSRK(tt, nil); !errors.Is(err, ErrSRKHandleMismatch) {
		t.Fatalf("ProvisionSRK: err = %v, want ErrSRKHandleMismatch", err)
	}
	// OpenSRK must likewise refuse: a mismatched object at the project
	// handle is not treated as "provisioned," never silently used.
	if _, _, err := OpenSRK(tt); !errors.Is(err, ErrSRKNotProvisioned) {
		t.Fatalf("OpenSRK: err = %v, want ErrSRKNotProvisioned", err)
	}
}

func TestProvisionSRK_IdempotentAtProjectHandle(t *testing.T) {
	tt := startSWTPM(t)
	h1, err := ProvisionSRK(tt, nil)
	if err != nil {
		t.Fatalf("ProvisionSRK (first): %v", err)
	}
	h2, err := ProvisionSRK(tt, nil)
	if err != nil {
		t.Fatalf("ProvisionSRK (second): %v", err)
	}
	if h1 != h2 || h1 != ProjectSRKHandle {
		t.Fatalf("ProvisionSRK handles = %#x, %#x, want both == ProjectSRKHandle %#x", h1, h2, ProjectSRKHandle)
	}
}

func TestOpenSRK_NotProvisionedIsError(t *testing.T) {
	tt := startSWTPM(t)
	if _, _, err := OpenSRK(tt); !errors.Is(err, ErrSRKNotProvisioned) {
		t.Fatalf("OpenSRK: err = %v, want ErrSRKNotProvisioned", err)
	}
}

func TestFindProvisionedSRK_FirstReadPublicGenericFailureSurfaces(t *testing.T) {
	tt := startSWTPM(t)
	f := &alwaysFailCommand{inner: tt, failCommand: cc(tpm2.TPMCCReadPublic)}
	if _, err := ProvisionSRK(f, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("ProvisionSRK: err = %v, want ErrTPMCommand", err)
	}
	if _, _, err := OpenSRK(f); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("OpenSRK: err = %v, want ErrTPMCommand", err)
	}
}

func TestProvisionSRK_EvictControlFailureSurfaces(t *testing.T) {
	tt := startSWTPM(t)
	f := &faultTPM{inner: tt, failCommand: cc(tpm2.TPMCCEvictControl), failOnCall: 1}
	if _, err := ProvisionSRK(f, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("ProvisionSRK: err = %v, want ErrTPMCommand", err)
	}
}

func TestSRKTemplateMatches_MismatchedFields(t *testing.T) {
	want, err := SRKTemplate.Contents()
	if err != nil {
		t.Fatalf("SRKTemplate.Contents: %v", err)
	}

	t.Run("wrong type", func(t *testing.T) {
		pub := *want
		pub.Type = tpm2.TPMAlgRSA
		if srkTemplateMatches(&pub) {
			t.Fatalf("srkTemplateMatches accepted a mismatched Type")
		}
	})
	t.Run("wrong name alg", func(t *testing.T) {
		pub := *want
		pub.NameAlg = tpm2.TPMAlgSHA384
		if srkTemplateMatches(&pub) {
			t.Fatalf("srkTemplateMatches accepted a mismatched NameAlg")
		}
	})
	t.Run("wrong object attributes", func(t *testing.T) {
		pub := *want
		pub.ObjectAttributes.Decrypt = false
		if srkTemplateMatches(&pub) {
			t.Fatalf("srkTemplateMatches accepted mismatched ObjectAttributes")
		}
	})
	t.Run("not ECC parameters", func(t *testing.T) {
		pub := *want
		pub.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}})
		if srkTemplateMatches(&pub) {
			t.Fatalf("srkTemplateMatches accepted non-ECC Parameters")
		}
	})
	t.Run("wrong curve", func(t *testing.T) {
		wantECC, err := want.Parameters.ECCDetail()
		if err != nil {
			t.Fatalf("ECCDetail: %v", err)
		}
		mismatched := *wantECC
		mismatched.CurveID = tpm2.TPMECCNistP384
		pub := *want
		pub.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &mismatched)
		if srkTemplateMatches(&pub) {
			t.Fatalf("srkTemplateMatches accepted a mismatched CurveID")
		}
	})
	t.Run("wrong symmetric algorithm", func(t *testing.T) {
		wantECC, err := want.Parameters.ECCDetail()
		if err != nil {
			t.Fatalf("ECCDetail: %v", err)
		}
		mismatched := *wantECC
		mismatched.Symmetric.Algorithm = tpm2.TPMAlgNull
		pub := *want
		pub.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &mismatched)
		if srkTemplateMatches(&pub) {
			t.Fatalf("srkTemplateMatches accepted a mismatched symmetric algorithm")
		}
	})
	t.Run("matches", func(t *testing.T) {
		if !srkTemplateMatches(want) {
			t.Fatalf("srkTemplateMatches rejected SRKTemplate's own content")
		}
	})
}

//go:build linux

package tetra

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
)

func TestRecordPeer(t *testing.T) {
	orig := peerCredFunc
	defer func() { peerCredFunc = orig }()

	sock := filepath.Join(t.TempDir(), "s")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		if c, err := lis.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	p := &peerTracker{}
	peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 77, nil }
	recordPeer(p, conn)
	if p.pid != 77 || p.dials != 1 {
		t.Fatalf("after recordPeer: pid %d dials %d", p.pid, p.dials)
	}
	peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 0, errors.New("no creds") }
	recordPeer(p, conn)
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	recordPeer(p, a) // not a unix socket
	if p.pid != 77 || p.dials != 1 {
		t.Fatalf("a failed or non-unix recordPeer changed the tracker: pid %d dials %d", p.pid, p.dials)
	}
}

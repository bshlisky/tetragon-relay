package tetra

import "testing"

func TestClientPeer(t *testing.T) {
	c := &Client{}
	if pid, dials := c.Peer(); pid != 0 || dials != 0 {
		t.Fatalf("Peer() without a tracker = %d, %d", pid, dials)
	}
	c.peer = &peerTracker{}
	c.peer.record(41)
	c.peer.record(42)
	if pid, dials := c.Peer(); pid != 42 || dials != 2 {
		t.Fatalf("Peer() = %d, %d; want 42, 2", pid, dials)
	}
}

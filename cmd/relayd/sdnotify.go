package main

import "net"

// sdNotify sends state to the systemd notification socket named by
// $NOTIFY_SOCKET (architecture doc 8.7's Type=notify unit), implementing
// just enough of the sd_notify(3) protocol for Part C4: a no-op (nil
// error) when NOTIFY_SOCKET is unset, matching every other sd_notify
// client's behavior when not run under systemd (e.g. a developer running
// the binary directly, or under a test harness). No systemd library
// dependency is added: the protocol is a single datagram write to a
// unix socket, which net.Dial("unixgram", ...) already does.
func sdNotify(notifySocket, state string) error {
	if notifySocket == "" {
		return nil
	}
	conn, err := net.Dial("unixgram", notifySocket) //nolint:gosec // G704: notifySocket comes from $NOTIFY_SOCKET, set by systemd itself for this unit, not attacker-controlled input
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(state))
	return err
}

package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTestSocket points SocketPath at a fresh temp dir for the duration of
// the test by overriding HOME, so tests never touch the real ~/.cifra.
// Uses a short path directly under /tmp rather than t.TempDir(), whose long
// macOS paths (/var/folders/.../T/...) overflow the ~104-byte sockaddr_un
// path limit.
func withTestSocket(t *testing.T) {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "cifra-agent-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	old := os.Getenv("HOME")
	_ = os.Setenv("HOME", home)
	t.Cleanup(func() {
		_ = os.Setenv("HOME", old)
		_ = os.RemoveAll(home)
	})
}

// startTestServer listens on a fresh test socket and runs Serve in the
// background until the listener is closed (by a "stop" request or test cleanup).
func startTestServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go Serve(ln)
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestSocketPath(t *testing.T) {
	withTestSocket(t)
	path, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if filepath.Base(path) != "agent.sock" {
		t.Errorf("unexpected socket path: %s", path)
	}
}

func TestIsRunning_FalseWhenNoAgent(t *testing.T) {
	withTestSocket(t)
	if IsRunning() {
		t.Error("expected IsRunning=false with no agent started")
	}
}

func TestListen_CreatesOwnerOnlySocket(t *testing.T) {
	withTestSocket(t)
	ln := startTestServer(t)
	_ = ln

	path, _ := SocketPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("socket perms = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat socket dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("socket dir perms = %o, want 0700", dirInfo.Mode().Perm())
	}
}

func TestListen_RejectsSecondListener(t *testing.T) {
	withTestSocket(t)
	startTestServer(t)

	if _, err := Listen(); err == nil {
		t.Error("expected error listening twice on the same socket")
	}
}

func TestUnlockAndGet_RoundTrip(t *testing.T) {
	withTestSocket(t)
	startTestServer(t)

	key := []byte("a-32-byte-fake-private-key-here")
	if err := unlockDirect("alice@example.com", key, time.Minute); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	got, ok := TryGet("alice@example.com")
	if !ok {
		t.Fatal("expected key to be cached")
	}
	if string(got) != string(key) {
		t.Errorf("got %q, want %q", got, key)
	}
}

func TestTryGet_NotCachedForUnknownID(t *testing.T) {
	withTestSocket(t)
	startTestServer(t)

	if _, ok := TryGet("nobody@example.com"); ok {
		t.Error("expected no key for an id that was never unlocked")
	}
}

func TestTryGet_FalseWhenNoAgentRunning(t *testing.T) {
	withTestSocket(t)
	if _, ok := TryGet("alice@example.com"); ok {
		t.Error("expected TryGet to fail closed when no agent is running")
	}
}

func TestUnlock_ExpiresAfterTTL(t *testing.T) {
	withTestSocket(t)
	startTestServer(t)

	// TTL is second-granularity on the wire (plenty for real multi-hour TTLs);
	// use the smallest representable value here rather than a sub-second one.
	key := []byte("short-lived-key")
	if err := unlockDirect("bob@example.com", key, time.Second); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if _, ok := TryGet("bob@example.com"); !ok {
		t.Fatal("expected key to be cached immediately after unlock")
	}

	time.Sleep(1200 * time.Millisecond)

	if _, ok := TryGet("bob@example.com"); ok {
		t.Error("expected key to be gone after TTL expiry")
	}
}

func TestLock_ClearsAllCachedKeys(t *testing.T) {
	withTestSocket(t)
	startTestServer(t)

	_ = unlockDirect("alice@example.com", []byte("key-a"), time.Minute)
	_ = unlockDirect("bob@example.com", []byte("key-b"), time.Minute)

	if err := Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	if _, ok := TryGet("alice@example.com"); ok {
		t.Error("expected alice's key to be cleared after Lock")
	}
	if _, ok := TryGet("bob@example.com"); ok {
		t.Error("expected bob's key to be cleared after Lock")
	}
}

func TestLock_NoopWhenNoAgentRunning(t *testing.T) {
	withTestSocket(t)
	if err := Lock(); err != nil {
		t.Errorf("Lock with no agent running should be a no-op, got: %v", err)
	}
}

func TestStatus_ReportsCachedIDs(t *testing.T) {
	withTestSocket(t)
	startTestServer(t)

	_ = unlockDirect("alice@example.com", []byte("key-a"), time.Minute)

	entries, err := Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "alice@example.com" {
		t.Errorf("unexpected status entries: %+v", entries)
	}
	if entries[0].ExpiresInSeconds <= 0 {
		t.Errorf("expected positive TTL remaining, got %d", entries[0].ExpiresInSeconds)
	}
}

func TestStatus_EmptyWhenNoAgentRunning(t *testing.T) {
	withTestSocket(t)
	entries, err := Status()
	if err != nil {
		t.Fatalf("Status with no agent running should not error, got: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries with no agent running, got: %+v", entries)
	}
}

func TestStop_TerminatesServeLoop(t *testing.T) {
	withTestSocket(t)
	ln, err := Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		Serve(ln)
		close(done)
	}()

	if !IsRunning() {
		t.Fatal("expected agent to be running before Stop")
	}
	if err := Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Stop")
	}

	if IsRunning() {
		t.Error("expected agent to no longer be reachable after Stop")
	}
}

func TestStop_NoopWhenNoAgentRunning(t *testing.T) {
	withTestSocket(t)
	if err := Stop(); err != nil {
		t.Errorf("Stop with no agent running should be a no-op, got: %v", err)
	}
}

// unlockDirect calls the wire protocol directly rather than through Unlock,
// so these tests don't depend on EnsureRunning's process-spawning path (the
// test server is already started via startTestServer).
func unlockDirect(id string, key []byte, ttl time.Duration) error {
	resp, err := roundTrip(request{Cmd: "unlock", ID: id, Key: encodeKey(key), TTLSeconds: int(ttl.Seconds())})
	if err != nil {
		return err
	}
	if !resp.OK {
		return &agentError{resp.Error}
	}
	return nil
}

type agentError struct{ msg string }

func (e *agentError) Error() string { return e.msg }
